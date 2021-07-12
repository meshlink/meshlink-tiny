/* MeshLink-tiny Example */

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

	ESP_ERROR_CHECK(esp_netif_init());

	ESP_ERROR_CHECK(esp_event_loop_create_default());
	esp_netif_create_default_wifi_sta();

	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));

	esp_event_handler_instance_t instance_any_id;
	esp_event_handler_instance_t instance_got_ip;
	ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
	                ESP_EVENT_ANY_ID,
	                &event_handler,
	                NULL,
	                &instance_any_id));
	ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
	                IP_EVENT_STA_GOT_IP,
	                &event_handler,
	                NULL,
	                &instance_got_ip));

	wifi_config_t wifi_config = {
		.sta = {
			.ssid = EXAMPLE_ESP_WIFI_SSID,
			.password = EXAMPLE_ESP_WIFI_PASS,
			/* Setting a password implies station will connect to all security modes including WEP/WPA.
			 * However these modes are deprecated and not advisable to be used. Incase your Access point
			 * doesn't support WPA2, these mode can be enabled by commenting below line */
			.threshold.authmode = WIFI_AUTH_WPA2_PSK,

			.pmf_cfg = {
				.capable = true,
				.required = false
			},
		},
	};
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
	ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
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

	/* The event will not be processed after unregister */
	ESP_ERROR_CHECK(esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, instance_got_ip));
	ESP_ERROR_CHECK(esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, instance_any_id));
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

	if(!meshlink_send(mesh, peer, argv[2], strlen(argv[2]))) {
		ESP_LOGE(TAG, "Send failed");
		return 1;
	}

	return 0;
}

static int quit_func(int argc, char **argv) {
	meshlink_close(mesh);
	mesh = NULL;
	ESP_LOGI(TAG, "Closed mesh");
	return 0;
}

static void mlt_main(void) {
	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, mlt_log);

	ESP_LOGI(TAG, "Starting MeshLink-tiny instance...");
	mesh = meshlink_open_ephemeral("esp32", "chat", DEV_CLASS_PORTABLE);

	if(!mesh) {
		ESP_LOGE(TAG, "Open failed!");
		return;
	}

	fflush(stdout);
	fsync(fileno(stdout));
	setvbuf(stdin, NULL, _IONBF, 0);

	esp_vfs_dev_uart_port_set_rx_line_endings(CONFIG_ESP_CONSOLE_UART_NUM, ESP_LINE_ENDINGS_CR);
	esp_vfs_dev_uart_port_set_tx_line_endings(CONFIG_ESP_CONSOLE_UART_NUM, ESP_LINE_ENDINGS_CRLF);

	const uart_config_t uart_config = {
		.baud_rate = CONFIG_ESP_CONSOLE_UART_BAUDRATE,
		.data_bits = UART_DATA_8_BITS,
		.parity = UART_PARITY_DISABLE,
		.stop_bits = UART_STOP_BITS_1,
#if CONFIG_IDF_TARGET_ESP32 || CONFIG_IDF_TARGET_ESP32S2
		.source_clk = UART_SCLK_REF_TICK,
#else
		.source_clk = UART_SCLK_XTAL,
#endif
	};
	/* Install UART driver for interrupt-driven reads and writes */
	ESP_ERROR_CHECK(uart_driver_install(CONFIG_ESP_CONSOLE_UART_NUM,
	                                    256, 0, 0, NULL, 0));
	ESP_ERROR_CHECK(uart_param_config(CONFIG_ESP_CONSOLE_UART_NUM, &uart_config));

	/* Tell VFS to use UART driver */
	esp_vfs_dev_uart_use_driver(CONFIG_ESP_CONSOLE_UART_NUM);

	esp_console_config_t console_config = {
		.max_cmdline_args = 8,
		.max_cmdline_length = 256,
	};

	ESP_ERROR_CHECK(esp_console_init(&console_config));

	linenoiseSetMultiLine(1);
	linenoiseHistorySetMaxLen(1);
	linenoiseAllowEmpty(false);

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

void app_main(void) {
	//Initialize NVS
	esp_err_t ret = nvs_flash_init();

	if(ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
		ESP_ERROR_CHECK(nvs_flash_erase());
		ret = nvs_flash_init();
	}

	ESP_ERROR_CHECK(ret);

	ESP_LOGI(TAG, "ESP_WIFI_MODE_STA");
	wifi_init_sta();
	mlt_main();
}
