#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <inttypes.h>

#include "pico/stdlib.h"
#include "hardware/gpio.h"
#include "pico/binary_info.h"
#include "hardware/flash.h"
#include "hardware/sync.h"
#include "pico/multicore.h"
#include "hardware/irq.h"
#include "hardware/adc.h"

#define SWITCH_OUT_GND 0
#define SWITCH_OUT_RF1 1


const uint LED_PIN = 25;
const uint SWITCH_PIN_A13_A13 = 15; // pin 20 on Pico, bottom left if USB faces up
const uint SWITCH_PIN_A13_A17 = 14; // pin 19 on Pico
const uint SWITCH_PIN_A11_A11 = 13;
const uint SWITCH_PIN_A11_A17 = 12;
const uint SWITCH_PIN_A17_A17 = 11;
const uint SWITCH_PIN_EXTRA0  = 10;
const uint SWITCH_PIN_EXTRA1  =  9;

const uint ALERTn_PIN  = 26;

// Uncomment this to enable logging to flash to enable persistency across reboots
// #define LOG_TO_FLASH

// Flash example from:
// https://github.com/raspberrypi/pico-examples/blob/master/flash/program/flash_program.c
// Interrupt example from:
// https://github.com/raspberrypi/pico-examples/blob/master/gpio/hello_gpio_irq/hello_gpio_irq.c

#define FLASH_LOG_OFFSET      (1600 * 1024)
#define FLASH_LOG_MAX_ENTRIES 128

const uint8_t *flash_log_contents = (const uint8_t *) (XIP_BASE + FLASH_LOG_OFFSET);

struct Event{
  absolute_time_t timestamp;
  uint32_t events;
};

struct Log{
  int nb_entries;
  struct Event events[FLASH_LOG_MAX_ENTRIES];
};

uint8_t log_buffer[FLASH_SECTOR_SIZE];
struct Log *event_log = (struct Log*)log_buffer;

void write_log() {
#ifdef LOG_TO_FLASH
  flash_range_erase(FLASH_LOG_OFFSET, FLASH_SECTOR_SIZE);
  flash_range_program(FLASH_LOG_OFFSET, log_buffer, FLASH_SECTOR_SIZE);
#endif  // LOG_TO_FLASH
}

void read_log() {
#ifdef LOG_TO_FLASH
  memcpy(event_log, flash_log_contents, sizeof(struct Log));
#endif  // LOG_TO_FLASH
}

static const char *gpio_irq_str[] = {
    "LEVEL_LOW",  // 0x1
    "LEVEL_HIGH", // 0x2
    "EDGE_FALL",  // 0x4
    "EDGE_RISE",  // 0x8
    "TEST"        // 0x10
};

void gpio_event_string(char *buf, uint32_t events) {
  for (uint i = 0; i < 5; i++) {
    uint mask = (1 << i);
    if (events & mask) {
      // Copy this event string into the user string
      const char *event_str = gpio_irq_str[i];
      while (*event_str != '\0') {
        *buf++ = *event_str++;
      }
      events &= ~mask;

      // If more events add ", "
      if (events) {
        *buf++ = ',';
        *buf++ = ' ';
      }
    }
  }
  *buf++ = '\0';
}

void print_log() {
  static uint8_t buf[256];
  read_log();

  int entries = (event_log->nb_entries > FLASH_LOG_MAX_ENTRIES) ? FLASH_LOG_MAX_ENTRIES : event_log->nb_entries;

  printf("Found %d log entries:\n", entries);
  for (int i = 0; i < entries; ++i) {
    gpio_event_string(buf, event_log->events[i].events);
    printf("  Timestamp=%" PRIu64 " -- Event=%s\n", to_us_since_boot(event_log->events[i].timestamp), buf);
  }
}

void log_event(uint32_t events) {
  uint32_t status = save_and_disable_interrupts();
  read_log();

  absolute_time_t current_time = get_absolute_time();
  struct Event event = {current_time, events};

  if (event_log->nb_entries < FLASH_LOG_MAX_ENTRIES) {
    event_log->events[event_log->nb_entries++] = event;
    
    write_log();
  }

  restore_interrupts(status);
}

void clear_log() {
  uint32_t status = save_and_disable_interrupts();
  memset(log_buffer, 0, FLASH_SECTOR_SIZE);

  write_log();
  restore_interrupts(status);
}

static void set_switch_low(uint pin)
{
  // Emulate open drain -> output and pull low
  gpio_set_dir(pin, GPIO_OUT);
  gpio_put(pin, 0);
}

static void set_switch_high(uint pin)
{
  // Emulate open drain -> output and pull low
  gpio_set_dir(pin, GPIO_OUT);
  gpio_put(pin, 1);
}

static void set_switch_high_z(uint pin)
{
  // Emulate open drain -> input = High-Z
  gpio_set_dir(pin, GPIO_IN);
}

// @param enable: 1 to connect input to output, 0 to connect output to ground
static void set_switch_state(uint pin, uint enable) {
  if (enable) {
    set_switch_high_z(pin);
  } else {
    set_switch_low(pin);
  }
}

static void send_acknowledge()
{
  printf("\nack\n");
}

static void send_not_acknowledge()
{
  printf("\nnack\n");
}

void core0_sio_irq() {
  while (multicore_fifo_rvalid())
    log_event(multicore_fifo_pop_blocking());

  multicore_fifo_clear_irq();
}

void core1_entry() {
  multicore_fifo_clear_irq();

  adc_init();

  // Make sure GPIO is high-impedance, no pullups etc
  adc_gpio_init(ALERTn_PIN);
  // Select ADC input 0 (GPIO26)
  adc_select_input(0);

  uint32_t previous_val = 0x0;

  while (1) {
    // Assuming max value == ADC_VREF == 3.3 V
    // Threshold = 0.3V => (0.3/3.3)*(1 << 12) = 372
    // Threshold = 0.9V => (0.9/3.3)*(1 << 12) = 1118
    uint16_t result = adc_read();

    if (previous_val != 0x1 && result < 372) {
      previous_val = 0x1;
      multicore_fifo_push_blocking(previous_val);
    } else if (previous_val != 0x2 && result >= 1118) {
      previous_val = 0x2;
      multicore_fifo_push_blocking(previous_val);
    }
  }
}


int main() 
{
  uint8_t b = 0;
  uint32_t data = 0;
  uint8_t buffer[32];
  uint64_t begin = 0, end = 0, duration;
  int c = -1;

  memset(log_buffer, 0, FLASH_SECTOR_SIZE);

  gpio_init(LED_PIN);
  gpio_set_dir(LED_PIN, GPIO_OUT);
  gpio_put(LED_PIN, 0);

  gpio_init(SWITCH_PIN_A11_A11);
  gpio_init(SWITCH_PIN_A11_A17);
  gpio_init(SWITCH_PIN_A13_A13);
  gpio_init(SWITCH_PIN_A13_A17);
  gpio_init(SWITCH_PIN_A17_A17);

  gpio_init(SWITCH_PIN_EXTRA0);
  gpio_init(SWITCH_PIN_EXTRA1);
 

  set_switch_state(SWITCH_PIN_A11_A11, SWITCH_OUT_RF1);
  set_switch_state(SWITCH_PIN_A13_A13, SWITCH_OUT_RF1);
  set_switch_state(SWITCH_PIN_A17_A17, SWITCH_OUT_RF1);

  set_switch_state(SWITCH_PIN_A11_A17, SWITCH_OUT_GND);
  set_switch_state(SWITCH_PIN_A13_A17, SWITCH_OUT_GND);

  set_switch_state(SWITCH_PIN_EXTRA0, SWITCH_OUT_GND);
  set_switch_state(SWITCH_PIN_EXTRA1, SWITCH_OUT_GND);

  stdio_init_all();

  multicore_launch_core1(core1_entry);

  irq_set_exclusive_handler(SIO_FIFO_IRQ_NUM(0), core0_sio_irq);
  irq_set_enabled(SIO_FIFO_IRQ_NUM(0), true);


  for(int i = 0; i < 5; i++)
  {
    sleep_ms(300);
    gpio_put(LED_PIN, 1);
    sleep_ms(300);
    gpio_put(LED_PIN, 0);
  }
  
  while (1)
  {  
    c = getchar_timeout_us(100000);
    
    if(c == (int)'e')
    {
      gpio_put(LED_PIN, 1);  
      set_switch_state(SWITCH_PIN_A11_A11, SWITCH_OUT_GND);
      set_switch_state(SWITCH_PIN_A13_A13, SWITCH_OUT_GND);
      set_switch_state(SWITCH_PIN_A17_A17, SWITCH_OUT_GND);

      set_switch_state(SWITCH_PIN_A11_A17, SWITCH_OUT_RF1);
      set_switch_state(SWITCH_PIN_A13_A17, SWITCH_OUT_RF1);
      send_acknowledge();
    }
    else if(c == (int)'d')
    {
      gpio_put(LED_PIN, 0);
      set_switch_state(SWITCH_PIN_A11_A11, SWITCH_OUT_RF1);
      set_switch_state(SWITCH_PIN_A13_A13, SWITCH_OUT_RF1);
      set_switch_state(SWITCH_PIN_A17_A17, SWITCH_OUT_RF1);

      set_switch_state(SWITCH_PIN_A11_A17, SWITCH_OUT_GND);
      set_switch_state(SWITCH_PIN_A13_A17, SWITCH_OUT_GND);
      send_acknowledge();
    }
    else if(c == (int)'p')
    {
      // 5 ms pulse
      gpio_put(LED_PIN, 1);  
      set_switch_state(SWITCH_PIN_A11_A11, SWITCH_OUT_GND);
      set_switch_state(SWITCH_PIN_A13_A13, SWITCH_OUT_GND);
      set_switch_state(SWITCH_PIN_A17_A17, SWITCH_OUT_GND);

      set_switch_state(SWITCH_PIN_A11_A17, SWITCH_OUT_RF1);
      set_switch_state(SWITCH_PIN_A13_A17, SWITCH_OUT_RF1);
      sleep_ms(5);
      set_switch_state(SWITCH_PIN_A11_A11, SWITCH_OUT_RF1);
      set_switch_state(SWITCH_PIN_A13_A13, SWITCH_OUT_RF1);
      set_switch_state(SWITCH_PIN_A17_A17, SWITCH_OUT_RF1);

      set_switch_state(SWITCH_PIN_A11_A17, SWITCH_OUT_GND);
      set_switch_state(SWITCH_PIN_A13_A17, SWITCH_OUT_GND);
      gpio_put(LED_PIN, 0);
      send_acknowledge();
    }
    else if(c == (int)'v')
    {
      send_acknowledge();
      printf("GPIO switcher v0.8\n");
    }
    else if(c == (int)'c')   // Clear ALERTn log
    {
      send_acknowledge();

      clear_log();
    }
    else if(c == (int)'l')   // Print ALERTn log
    {
      send_acknowledge();

      print_log();
    }
    else if(c == PICO_ERROR_TIMEOUT)
    {
      // Timeout, no command received
    }
    else
    {
      // Unknown command
      send_not_acknowledge();
    }
  }

  return 0;
}


