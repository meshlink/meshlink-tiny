/* MeshLink-tiny Example */

typedef void *List_t;
typedef void *ListItem_t;

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_console.h"
#include "esp_vfs_dev.h"
#include "driver/uart.h"
#include "linenoise/linenoise.h"
#include "argtable3/argtable3.h"
#include "nvs.h"
#include "nvs_flash.h"

#include "lwip/err.h"
#include "lwip/sys.h"

#include "meshlink-tiny.h"

/* The examples use WiFi configuration that you can set via project configuration menu

   If you'd rather not, just change the below entries to strings with
   the config you want - ie #define EXAMPLE_WIFI_SSID "mywifissid"
*/
#define EXAMPLE_ESP_WIFI_SSID      CONFIG_ESP_WIFI_SSID
#define EXAMPLE_ESP_WIFI_PASS      CONFIG_ESP_WIFI_PASSWORD
#define EXAMPLE_ESP_MAXIMUM_RETRY  CONFIG_ESP_MAXIMUM_RETRY

/* FreeRTOS event group to signal when we are connected*/
static EventGroupHandle_t s_wifi_event_group;

/* The event group allows multiple bits for each event, but we only care about two events:
 * - we are connected to the AP with an IP
 * - we failed to connect after the maximum amount of retries */
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

static const char *TAG = "wifi station";

static int s_retry_num = 0;

static void event_handler(void *arg, esp_event_base_t event_base,
                          int32_t event_id, void *event_data) {
	if(event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
		esp_wifi_connect();
	} else if(event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
		if(s_retry_num < EXAMPLE_ESP_MAXIMUM_RETRY) {
			esp_wifi_connect();
			s_retry_num++;
			ESP_LOGI(TAG, "retry to connect to the AP");
		} else {
			xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
		}

		ESP_LOGI(TAG, "connect to the AP fail");
	} else if(event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
		ip_event_got_ip_t *event = (ip_event_got_ip_t *) event_data;
		ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
		s_retry_num = 0;
		xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
	}
}

void wifi_init_sta(void) {
	s_wifi_event_group = xEventGroupCreate();

	tcpip_adapter_init();

	ESP_ERROR_CHECK(esp_event_loop_create_default());

	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));

	ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL));
	ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL));

	wifi_config_t wifi_config = {
		.sta = {
			.ssid = EXAMPLE_ESP_WIFI_SSID,
			.password = EXAMPLE_ESP_WIFI_PASS
		},
	};

	/* Setting a password implies station will connect to all security modes including WEP/WPA.
	    * However these modes are deprecated and not advisable to be used. Incase your Access point
	    * doesn't support WPA2, these mode can be enabled by commenting below line */

	if(strlen((char *)wifi_config.sta.password)) {
		wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
	}

	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
	ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config));
	ESP_ERROR_CHECK(esp_wifi_start());

	ESP_LOGI(TAG, "wifi_init_sta finished.");

	/* Waiting until either the connection is established (WIFI_CONNECTED_BIT) or connection failed for the maximum
	 * number of re-tries (WIFI_FAIL_BIT). The bits are set by event_handler() (see above) */
	EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
	                                       WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
	                                       pdFALSE,
	                                       pdFALSE,
	                                       portMAX_DELAY);

	/* xEventGroupWaitBits() returns the bits before the call returned, hence we can test which event actually
	 * happened. */
	if(bits & WIFI_CONNECTED_BIT) {
		ESP_LOGI(TAG, "connected to ap SSID:%s password:%s",
		         EXAMPLE_ESP_WIFI_SSID, EXAMPLE_ESP_WIFI_PASS);
	} else if(bits & WIFI_FAIL_BIT) {
		ESP_LOGI(TAG, "Failed to connect to SSID:%s, password:%s",
		         EXAMPLE_ESP_WIFI_SSID, EXAMPLE_ESP_WIFI_PASS);
	} else {
		ESP_LOGE(TAG, "UNEXPECTED EVENT");
	}

	ESP_ERROR_CHECK(esp_event_handler_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler));
	ESP_ERROR_CHECK(esp_event_handler_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler));
	vEventGroupDelete(s_wifi_event_group);
}


static void mlt_log(meshlink_handle_t *mesh, meshlink_log_level_t leve, const char *text) {
	ESP_LOGI(TAG, "Log: %s", text);
}

meshlink_handle_t *mesh = NULL;

static void receive(meshlink_handle_t *mesh, meshlink_node_t *from, const void *data, size_t len) {
	char *str = (char *)data;
	str[len] = 0;
	ESP_LOGI(TAG, "%s says: %s", from->name, str);
}

static int join_func(int argc, char **argv) {
	if(argc < 2) {
		return 1;
	}

	if(!meshlink_join(mesh, argv[1])) {
		ESP_LOGE(TAG, "Join failed");
		return 1;
	}

	ESP_LOGI(TAG, "Join completed");

	meshlink_set_receive_cb(mesh, receive);

	if(!meshlink_start(mesh)) {
		ESP_LOGE(TAG, "Could not start mesh!");
		return 1;
	}

	uint32_t heap_size = heap_caps_get_minimum_free_size(MALLOC_CAP_32BIT);
	uint32_t stack_size = uxTaskGetStackHighWaterMark(NULL);
	ESP_LOGI(TAG, "min heap size: %u  stack size: %u", heap_size, stack_size);

	return 0;
}

static int say_func(int argc, char **argv) {
	if(argc < 3) {
		return 1;
	}

	meshlink_node_t *peer = meshlink_get_node(mesh, argv[1]);

	if(!peer) {
		ESP_LOGE(TAG, "Peer not found");
		return 1;
	}

	if(!meshlink_send(mesh, peer, argv[2], strlen(argv[2]) + 1)) {
		ESP_LOGE(TAG, "Send failed");
		return 1;
	}

	return 0;
}

static int quit_func(int argc, char **argv) {
	meshlink_close(mesh);
	mesh = NULL;
	ESP_LOGI(TAG, "Closed mesh");
	uint32_t heap_size = heap_caps_get_minimum_free_size(MALLOC_CAP_32BIT);
	uint32_t stack_size = uxTaskGetStackHighWaterMark(NULL);
	ESP_LOGI(TAG, "min heap size: %u  stack size: %u", heap_size, stack_size);
	return 0;
}

static void mlt_main(void) {
	uint32_t heap_size = heap_caps_get_minimum_free_size(MALLOC_CAP_32BIT);
	uint32_t stack_size = uxTaskGetStackHighWaterMark(NULL);
	ESP_LOGI(TAG, "min heap size: %u  stack size: %u", heap_size, stack_size);

	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, mlt_log);

	ESP_LOGI(TAG, "Starting MeshLink-tiny instance...");
	mesh = meshlink_open_ephemeral("esp32", "chat", DEV_CLASS_PORTABLE);

	if(!mesh) {
		ESP_LOGE(TAG, "Open failed!");
		return;
	}

	esp_console_cmd_t join_cmd = {
		.command = "join",
		.help = "Join a mesh",
		.func = join_func,
	};

	esp_console_cmd_t say_cmd = {
		.command = "say",
		.help = "Say something",
		.func = say_func,
	};

	esp_console_cmd_t quit_cmd = {
		.command = "quit",
		.help = "Quit",
		.func = quit_func,
	};

	esp_console_cmd_register(&join_cmd);
	esp_console_cmd_register(&say_cmd);
	esp_console_cmd_register(&quit_cmd);
	esp_console_register_help_command();

	while(mesh) {
		char *line = linenoise("> ");

		if(!line) {
			continue;
		}

		linenoiseHistoryAdd(line);
		int ret;
		esp_console_run(line, &ret);
		linenoiseFree(line);
	}

	ESP_LOGI(TAG, "App quit");
	esp_console_deinit();
}

static void initialize_nvs() {
	esp_err_t err = nvs_flash_init();

	if(err == ESP_ERR_NVS_NO_FREE_PAGES) {
		ESP_ERROR_CHECK(nvs_flash_erase());
		err = nvs_flash_init();
	}

	ESP_ERROR_CHECK(err);
}

static void initialize_console() {
	/* Disable buffering on stdin */
	setvbuf(stdin, NULL, _IONBF, 0);

	/* Minicom, screen, idf_monitor send CR when ENTER key is pressed */
	esp_vfs_dev_uart_set_rx_line_endings(ESP_LINE_ENDINGS_CR);
	/* Move the caret to the beginning of the next line on '\n' */
	esp_vfs_dev_uart_set_tx_line_endings(ESP_LINE_ENDINGS_CRLF);

	/* Configure UART. Note that REF_TICK is used so that the baud rate remains
	 * correct while APB frequency is changing in light sleep mode.
	 */
	uart_config_t uart_config = {
		.baud_rate = CONFIG_ESP_CONSOLE_UART_BAUDRATE,
		.data_bits = UART_DATA_8_BITS,
		.parity = UART_PARITY_DISABLE,
		.stop_bits = UART_STOP_BITS_1,
	};
	ESP_ERROR_CHECK(uart_param_config(CONFIG_ESP_CONSOLE_UART_NUM, &uart_config));

	/* Install UART driver for interrupt-driven reads and writes */
	ESP_ERROR_CHECK(uart_driver_install(CONFIG_ESP_CONSOLE_UART_NUM,
	                                    256, 0, 0, NULL, 0));

	/* Tell VFS to use UART driver */
	esp_vfs_dev_uart_use_driver(CONFIG_ESP_CONSOLE_UART_NUM);

	/* Initialize the console */
	esp_console_config_t console_config = {
		.max_cmdline_args = 8,
		.max_cmdline_length = 256,
#if CONFIG_LOG_COLORS
		.hint_color = atoi(LOG_COLOR_CYAN)
#endif
	};
	ESP_ERROR_CHECK(esp_console_init(&console_config));
}


void app_main(void) {
	uint32_t heap_size = heap_caps_get_minimum_free_size(MALLOC_CAP_32BIT);
	uint32_t stack_size = uxTaskGetStackHighWaterMark(NULL);
	printf("min heap size: %u  stack size: %u\n", heap_size, stack_size);

	/* Print chip information */
	esp_chip_info_t chip_info;
	esp_chip_info(&chip_info);
	printf("This is ESP8266 chip with %d CPU cores, WiFi, ",
	       chip_info.cores);

	printf("silicon revision %d, ", chip_info.revision);

	printf("%dMB %s flash\n", spi_flash_get_chip_size() / (1024 * 1024),
	       (chip_info.features & CHIP_FEATURE_EMB_FLASH) ? "embedded" : "external");

	initialize_nvs();
	initialize_console();

	esp_console_register_help_command();

	ESP_LOGI(TAG, "ESP_WIFI_MODE_STA");
	wifi_init_sta();
	mlt_main();
}
