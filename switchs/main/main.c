/* HTTPS GET Example using plain mbedTLS sockets
 *
 * Contacts the howsmyssl.com API via TLS v1.2 and reads a JSON
 * response.
 *
 * Adapted from the ssl_client1 example in mbedtls.
 *
 * Original Copyright (C) 2006-2016, ARM Limited, All Rights Reserved, Apache 2.0 License.
 * Additions Copyright (C) Copyright 2015-2016 Espressif Systems (Shanghai) PTE LTD, Apache 2.0 License.
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event_loop.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"

#include "mbedtls/platform.h"
#include "mbedtls/net.h"
#include "mbedtls/esp_debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"

#include "cJSON.h"
//#include "driver/ledc.h"
//#include "freertos/queue.h"
#include "driver/gpio.h"

#include "esp_partition.h"
//#include "nvs_flash.h"
#include "nvs.h"

#include "WebSocket_Task.h"

/* The examples use simple WiFi configuration that you can set via
   'make menuconfig'.
   If you'd rather not, just change the below entries to strings with
   the config you want - ie #define EXAMPLE_WIFI_SSID "mywifissid"
*/
//char *EXAMPLE_WIFI_SSID = "Leon A.one";//CONFIG_WIFI_SSID MOBILE STAR WiFi
//char *EXAMPLE_WIFI_PASS = "11330232";//CONFIG_WIFI_PASSWORD mobiist@r2017
unsigned char uc_ssid[] = "Leon A.one";
unsigned char uc_pw[] = "11330232";

/* FreeRTOS event group to signal when we are connected & ready to make a request */
static EventGroupHandle_t wifi_event_group;

/* The event group allows multiple bits for each event,
   but we only care about one event - are we connected
   to the AP with an IP? */
const int CONNECTED_BIT = BIT0;

/* Constants that aren't configurable in menuconfig */
//#define WEB_SERVER "www.howsmyssl.com"
//#define WEB_PORT "443"
//#define WEB_URL "https://www.howsmyssl.com/a/check"
#define WEB_SERVER "linhomes-afa8a.firebaseio.com"
#define WEB_PORT "443"
#define WEB_URL "/switchs/"

#define GPIO_OUTPUT_PIN_SEL  ((1<<GPIO_NUM_18))
#define ESP_INTR_FLAG_DEFAULT 0

#define GPIO_INPUT_PIN_SEL  ((1<<GPIO_NUM_14))

static const char *TAG = "example";
//static int count_time = 0;

//static const char *REQUEST = "GET " WEB_URL " HTTP/1.0\r\n"
//    "Host: "WEB_SERVER"\r\n"
//    "User-Agent: esp-idf/1.0 esp32\r\n"
//    "\r\n";

//static const char *REQUEST = "PUT " WEB_URL " HTTP/1.0\r\n"
//"User-Agent: esp-idf/1.0 esp32\r\n"
//"Connection: close\r\n" //general header
//"Host: "WEB_SERVER"\r\n" //request header
//"Content-Type: application/json\r\n" //entity header
//"Content-Length: 13\r\n" //entity header
//"\r\n"
//"{\"pwr\":\"off\"}";
char *REQUEST = "";
void info_listener(char argv[]);

xTaskHandle TaskHandle_get;
xTaskHandle TaskHandle_push_i;
xTaskHandle TaskHandle_push_d;
xTaskHandle TaskHandle_ctrl_16;
xTaskHandle TaskHandle_ctrl_17;
xTaskHandle TaskHandle_ctrl_18;
xTaskHandle TaskHandle_ctrl_19;

/* Root cert for howsmyssl.com, taken from server_root_cert.pem
   The PEM file was extracted from the output of this command:
   openssl s_client -showcerts -connect www.howsmyssl.com:443 </dev/null
   The CA root cert is the last cert given in the chain of certs.
   To embed it in the app binary, the PEM file is named
   in the component.mk COMPONENT_EMBED_TXTFILES variable.
*/
extern const uint8_t server_root_cert_pem_start[] asm("_binary_server_root_cert_pem_start");
extern const uint8_t server_root_cert_pem_end[]   asm("_binary_server_root_cert_pem_end");

//WebSocket frame receive queue
QueueHandle_t WebSocket_rx_queue;
static xQueueHandle gpio_evt_queue = NULL;

static int handle_nvs(const char *key, int val, int flag){
	esp_err_t err;
	nvs_handle my_handle;
	int32_t status = -1;
	err = nvs_open("storage", NVS_READWRITE, &my_handle);
	if (err != ESP_OK) {
		printf("Error (%d) opening NVS handle!\n", err);
	} else {
		printf("Done\n");

		// Write
		if(flag == 1){
			// Write
			printf("Updating restart counter in NVS ... ");
			err = nvs_set_i32(my_handle, key, val);
			printf((err != ESP_OK) ? "Failed!\n" : "Done\n");

			// Commit written value.
			// After setting any values, nvs_commit() must be called to ensure changes are written
			// to flash storage. Implementations may write to storage at other times,
			// but this is not guaranteed.
			printf("Committing updates in NVS ... ");
			err = nvs_commit(my_handle);
			printf((err != ESP_OK) ? "Failed!\n" : "Done\n");
			status = err;
		} else{ // Read
			printf("Reading restart counter from NVS ... ");
//			int32_t nvs_val = 0; // value will default to 0, if not set yet in NVS
			err = nvs_get_i32(my_handle, key, &status);
			ESP_LOGI(TAG, "\ncJSON_Print-----------> %d\n", err);
			switch (err) {
				case ESP_OK:
					printf("NVS read\n");
					printf("Key %s = %d\n", key, status);
					break;
				case ESP_ERR_NVS_NOT_FOUND:
					printf("The value is not initialized yet!\n");
					break;
				default :
					printf("Error (%d) reading!\n", err);
			}
		}

		// Close
		nvs_close(my_handle);
	}
	return status;
}

static void IRAM_ATTR gpio_isr_handler(void* arg){
    uint32_t gpio_num = (uint32_t) arg;
    xQueueSendFromISR(gpio_evt_queue, &gpio_num, NULL);
}

static void gpio_task_example(void* arg){
    uint32_t io_num;
    for(;;) {
        if(xQueueReceive(gpio_evt_queue, &io_num, portMAX_DELAY)) {
            printf("GPIO[%d] intr, val: %d\n", io_num, gpio_get_level(io_num));
            if(io_num == GPIO_NUM_13){
            	if(handle_nvs("w_mode", 1, 1) == ESP_OK){ // keo chan 13 len cao thi switch sang mode ap
					esp_restart();
				}
            }
        }
    }
}

static esp_err_t event_handler(void *ctx, system_event_t *event){
//	ESP_LOGI(TAG, "\n event_id: %d \n", event->event_id);
    switch(event->event_id) {
    case SYSTEM_EVENT_STA_START:
        esp_wifi_connect();
        break;
    case SYSTEM_EVENT_STA_GOT_IP:
//    	count_time = 0;
		handle_nvs("w_mode", 0, 1);
        xEventGroupSetBits(wifi_event_group, CONNECTED_BIT);
        break;
    case SYSTEM_EVENT_STA_DISCONNECTED:
        /* This is a workaround as ESP32 WiFi libs don't currently
           auto-reassociate. */
//    	count_time++;
//    	if(count_time > 9){
//    		if(handle_nvs("w_mode", 1, 1) == 1){
//				esp_restart();
//				break;
//    		}
//    	}
    	esp_wifi_connect();
        xEventGroupClearBits(wifi_event_group, CONNECTED_BIT);
        break;
    default:
        break;
    }
    return ESP_OK;
}

static void initialise_wifi(void){
    tcpip_adapter_init();
    wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK( esp_event_loop_init(event_handler, NULL) );
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
    ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );

    wifi_sta_config_t sta = {
    	.ssid = "Leon ESP32",
		.password = "11330232"
    };
    memcpy(sta.ssid, uc_ssid, sizeof(uc_ssid));
    memcpy(sta.password, uc_pw, sizeof(uc_pw));
    wifi_config_t wifi_config = {
        .sta = sta,
    };
//    wifi_config.sta.ssid = "";//(const char*)EXAMPLE_WIFI_SSID;
//    wifi_config.sta.password = "";//(const char*)EXAMPLE_WIFI_PASS;
    ESP_LOGI(TAG, "Setting WiFi configuration SSID %s...", wifi_config.sta.ssid);
    ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK( esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config) );
    ESP_ERROR_CHECK( esp_wifi_start() );
}

static void initialise_ap(void){
    tcpip_adapter_init();
    wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK( esp_event_loop_init(event_handler, NULL) );
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
    ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );

    wifi_ap_config_t ap = {
    	.ssid = "Leon ESP32",
		.password = "11330232",
		.authmode = WIFI_AUTH_WPA2_PSK
    };
//    memcpy(ap.ssid, uc_ssid, sizeof(uc_ssid));
//    memcpy(ap.password, uc_pw, sizeof(uc_pw));
    wifi_config_t wifi_config = {
        .ap = ap,
    };
//    wifi_config.sta.ssid = "";//(const char*)EXAMPLE_WIFI_SSID;
//    wifi_config.sta.password = "";//(const char*)EXAMPLE_WIFI_PASS;
    ESP_LOGI(TAG, "Setting AP configuration SSID %s...", wifi_config.ap.ssid);
    ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_AP) );
    ESP_ERROR_CHECK( esp_wifi_set_config(ESP_IF_WIFI_AP, &wifi_config) );
    ESP_ERROR_CHECK( esp_wifi_start() );
}

static void https_get_task(void *pvParameters){
    char buf[512];
    int ret, flags, len;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_x509_crt cacert;
    mbedtls_ssl_config conf;
    mbedtls_net_context server_fd;

    mbedtls_ssl_init(&ssl);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    ESP_LOGI(TAG, "Seeding the random number generator");

    mbedtls_ssl_config_init(&conf);

    mbedtls_entropy_init(&entropy);
    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    NULL, 0)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed returned %d", ret);
        abort();
    }

    ESP_LOGI(TAG, "Loading the CA root certificate...");

    ret = mbedtls_x509_crt_parse(&cacert, server_root_cert_pem_start, server_root_cert_pem_end-server_root_cert_pem_start);

    if(ret < 0)
    {
        ESP_LOGE(TAG, "mbedtls_x509_crt_parse returned -0x%x\n\n", -ret);
        abort();
    }

    ESP_LOGI(TAG, "Setting hostname for TLS session...");

     /* Hostname set here should match CN in server certificate */
    if((ret = mbedtls_ssl_set_hostname(&ssl, WEB_SERVER)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_set_hostname returned -0x%x", -ret);
        abort();
    }

    ESP_LOGI(TAG, "Setting up the SSL/TLS structure...");

	mbedtls_ssl_conf_read_timeout(&conf, 15000);
    if((ret = mbedtls_ssl_config_defaults(&conf,
                                          MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_config_defaults returned %d", ret);
        goto exit;
    }

    /* MBEDTLS_SSL_VERIFY_OPTIONAL is bad for security, in this example it will print
       a warning if CA verification fails but it will continue to connect.
       You should consider using MBEDTLS_SSL_VERIFY_REQUIRED in your own code.
    */
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
#ifdef CONFIG_MBEDTLS_DEBUG
    mbedtls_esp_enable_debug_log(&conf, 4);
#endif

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_setup returned -0x%x\n\n", -ret);
        goto exit;
    }

    while(1) {
        /* Wait for the callback to set the CONNECTED_BIT in the
           event group.
        */
        xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT,
                            false, true, portMAX_DELAY);
        ESP_LOGI(TAG, "Connected to AP");

        mbedtls_net_init(&server_fd);

        ESP_LOGI(TAG, "Connecting to %s:%s...", WEB_SERVER, WEB_PORT);

        if ((ret = mbedtls_net_connect(&server_fd, WEB_SERVER,
                                      WEB_PORT, MBEDTLS_NET_PROTO_TCP)) != 0)
        {
            ESP_LOGE(TAG, "mbedtls_net_connect returned -%x", -ret);
            goto exit;
        }

        ESP_LOGI(TAG, "Connected.");

//        mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
        mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);

        ESP_LOGI(TAG, "Performing the SSL/TLS handshake...");

        while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
        {
            ESP_LOGE(TAG, "mbedtls_ssl_handshake returned -0x%x", -ret);
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            {
                ESP_LOGE(TAG, "mbedtls_ssl_handshake returned -0x%x", -ret);
                goto exit;
            }
        }

        ESP_LOGI(TAG, "Verifying peer X.509 certificate...");

        if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0)
        {
            /* In real life, we probably want to close connection if ret != 0 */
            ESP_LOGW(TAG, "Failed to verify peer certificate!");
            bzero(buf, sizeof(buf));
            mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", flags);
            ESP_LOGW(TAG, "verification info: %s", buf);
        }
        else {
            ESP_LOGI(TAG, "Certificate verified.");
        }

        ESP_LOGI(TAG, "Writing HTTP request...");

        uint8_t addr[6];
		esp_efuse_mac_get_default(addr);
		char mac[18];
		snprintf(mac, sizeof(mac), "%02x-%02x-%02x-%02x-%02x-%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
//		printf("%s\n", mac);

		char url[68];
		strcpy(url, WEB_URL);
		strcat( url, mac);
		strcat( url, ".json"); // access_token will be required in the future
		printf("%s\n", url);

		char request[100] = "GET ";
		strcat(request, url);
		strcat(request, " HTTP/1.0\r\n");
		strcat(request, "User-Agent: esp-idf/1.0 esp32\r\n");
		strcat(request, "Connection: close\r\n");
		strcat(request, "Host: linhomes-afa8a.firebaseio.com\r\n");
		strcat(request, "User-Agent: esp-idf/1.0 esp32\r\n");
		strcat(request, "Accept: application/json\r\n");
		strcat(request, "\r\n");
//		REQUEST = request;
		printf("%s\n", request);
		while((ret = mbedtls_ssl_write(&ssl, (const unsigned char *)request, strlen(request))) <= 0){
			if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE){
				ESP_LOGE(TAG, "mbedtls_ssl_write returned -0x%x", -ret);
				goto exit;
			}
		}

		len = ret;
		ESP_LOGI(TAG, "%d bytes written", len);
		ESP_LOGI(TAG, "Reading HTTP response...");
//		mbedtls_printf("%s", buf);
		do{
			len = sizeof(buf) - 1;
			bzero(buf, sizeof(buf));
			ret = mbedtls_ssl_read(&ssl, (unsigned char *)buf, len);

			if(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE){
				continue;
			}
			if(ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
				ret = 0;
				break;
			}
			if(ret < 0){
				ESP_LOGE(TAG, "mbedtls_ssl_read returned -0x%x", -ret);
				break;
			}
			if(ret == 0){
				ESP_LOGI(TAG, "connection closed");
				break;
			}
			info_listener(buf);

//			ESP_LOGI(TAG, "\ninfo_listener----------->\n");
//			mbedtls_printf("%s", buf);
		} while(1);

        mbedtls_ssl_close_notify(&ssl);

    exit:
        mbedtls_ssl_session_reset(&ssl);
        mbedtls_net_free(&server_fd);

        if(ret != 0)
        {
            mbedtls_strerror(ret, buf, 100);
            ESP_LOGE(TAG, "Last error was: -0x%x - %s", -ret, buf);
        }

        // delay 3 seconds
//        for(int countdown = 2; countdown >= 0; countdown--) {
//            ESP_LOGI(TAG, "%d...", countdown);
//            vTaskDelay(1000 / portTICK_PERIOD_MS);
//        }
        vTaskDelay(1000 / portTICK_PERIOD_MS);
        ESP_LOGI(TAG, "Starting again!");
        vTaskDelete(TaskHandle_get);
    }
}

static void push_listener(void *pvParameters){
	return;
    vTaskDelete(TaskHandle_push_i);
    char buf[512];
    int ret, flags, len;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_x509_crt cacert;
    mbedtls_ssl_config conf;
    mbedtls_net_context server_fd;

    mbedtls_ssl_init(&ssl);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    ESP_LOGI(TAG, "Seeding the random number generator");

    mbedtls_ssl_config_init(&conf);

    mbedtls_entropy_init(&entropy);
    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    NULL, 0)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed returned %d", ret);
        abort();
    }

    ESP_LOGI(TAG, "Loading the CA root certificate...");

    ret = mbedtls_x509_crt_parse(&cacert, server_root_cert_pem_start,
                                 server_root_cert_pem_end-server_root_cert_pem_start);

    if(ret < 0)
    {
        ESP_LOGE(TAG, "mbedtls_x509_crt_parse returned -0x%x\n\n", -ret);
        abort();
    }

    ESP_LOGI(TAG, "Setting hostname for TLS session...");

     /* Hostname set here should match CN in server certificate */
    if((ret = mbedtls_ssl_set_hostname(&ssl, WEB_SERVER)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_set_hostname returned -0x%x", -ret);
        abort();
    }

    ESP_LOGI(TAG, "Setting up the SSL/TLS structure...");

    if((ret = mbedtls_ssl_config_defaults(&conf,
                                          MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_config_defaults returned %d", ret);
        goto exit;
    }

    /* MBEDTLS_SSL_VERIFY_OPTIONAL is bad for security, in this example it will print
       a warning if CA verification fails but it will continue to connect.
       You should consider using MBEDTLS_SSL_VERIFY_REQUIRED in your own code.
    */
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_conf_read_timeout(&conf, 3000);
#ifdef CONFIG_MBEDTLS_DEBUG
    mbedtls_esp_enable_debug_log(&conf, 4);
#endif

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_setup returned -0x%x\n\n", -ret);
        goto exit;
    }

    while(1) {
        /* Wait for the callback to set the CONNECTED_BIT in the
           event group.
        */
        xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT,
                            false, true, portMAX_DELAY);
        ESP_LOGI(TAG, "Connected to AP");

        mbedtls_net_init(&server_fd);

        ESP_LOGI(TAG, "Connecting to %s:%s...", WEB_SERVER, WEB_PORT);

        if ((ret = mbedtls_net_connect(&server_fd, WEB_SERVER,
                                      WEB_PORT, MBEDTLS_NET_PROTO_TCP)) != 0)
        {
            ESP_LOGE(TAG, "mbedtls_net_connect returned -%x", -ret);
            goto exit;
        }

        ESP_LOGI(TAG, "Connected.");

        //        mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
		mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);

        ESP_LOGI(TAG, "Performing the SSL/TLS handshake...");

        while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
        {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            {
                ESP_LOGE(TAG, "mbedtls_ssl_handshake returned -0x%x", -ret);
                goto exit;
            }
        }

        ESP_LOGI(TAG, "Verifying peer X.509 certificate...");

        if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0)
        {
            /* In real life, we probably want to close connection if ret != 0 */
            ESP_LOGW(TAG, "Failed to verify peer certificate!");
            bzero(buf, sizeof(buf));
            mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", flags);
            ESP_LOGW(TAG, "verification info: %s", buf);
        }
        else {
            ESP_LOGI(TAG, "Certificate verified.");
        }

        ESP_LOGI(TAG, "Writing HTTP request...");

    	int pin = (int)pvParameters;
    	int state = gpio_get_level(pin - 4);
    	uint8_t addr[6];
    	esp_efuse_mac_get_default(addr);
    	char mac[18];
    	snprintf(mac, sizeof(mac), "%02x-%02x-%02x-%02x-%02x-%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    	char spin[11];
    	snprintf(spin, sizeof(spin), "%d", pin);
    	char url[68];
    	strcpy(url, WEB_URL);
    	strcat( url, mac);
    	strcat( url, "/ps/");
    	strcat( url, spin);
    	strcat( url, "/.json");
    	printf("%s\n", url);

		char data[26];
		snprintf(data, sizeof(data), "{\"res\":%d, \"sta\":1}", state);
		char *post = data;
		char len_post[10];
		snprintf(len_post, sizeof(len_post), "%d", strlen(data));

		char request[300] = "PATCH ";
		strcat(request, url);
		strcat(request, " HTTP/1.0\r\n");
		strcat(request, "User-Agent: esp-idf/1.0 esp32\r\n");
		strcat(request, "Connection: close\r\n");
		strcat(request, "Host: linhomes-afa8a.firebaseio.com\r\n");
		strcat(request, "Content-Type: application/json\r\n");
		strcat(request, "Content-Length: ");
		strcat(request, len_post);
		strcat(request, "\r\n");
		strcat(request, "\r\n");
		strcat(request, post);
//		REQUEST = request;
		printf("%s\n", request);
		while((ret = mbedtls_ssl_write(&ssl, (const unsigned char *)request, strlen(request))) <= 0){
			if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE){
				ESP_LOGE(TAG, "mbedtls_ssl_write returned -0x%x", -ret);
				goto exit;
			}
		}

		len = ret;
		ESP_LOGI(TAG, "%d bytes written", len);
		ESP_LOGI(TAG, "Reading HTTP response...");
//		mbedtls_printf("%s", buf);
		do{
			len = sizeof(buf) - 1;
			bzero(buf, sizeof(buf));
			ret = mbedtls_ssl_read(&ssl, (unsigned char *)buf, len);

			if(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE){
				continue;
			}
			if(ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
				ret = 0;
				break;
			}
			if(ret < 0){
				ESP_LOGE(TAG, "mbedtls_ssl_read returned -0x%x", -ret);
				break;
			}
			if(ret == 0){
				ESP_LOGI(TAG, "connection closed");
				break;
			}
//			info_listener(buf);
			mbedtls_printf("%s", buf);
		} while(1);

        mbedtls_ssl_close_notify(&ssl);

    exit:
        mbedtls_ssl_session_reset(&ssl);
        mbedtls_net_free(&server_fd);

//        if(ret != 0)
//        {
//            mbedtls_strerror(ret, buf, 100);
//            ESP_LOGE(TAG, "Last error was: -0x%x - %s", -ret, buf);
//        }
//        return;
//    	vTaskDelete(NULL);
//        for(int countdown = 10; countdown >= 0; countdown--) {
//            ESP_LOGI(TAG, "%d...", countdown);
//            vTaskDelay(1000 / portTICK_PERIOD_MS);
//        }
//        ESP_LOGI(TAG, "Starting again!");
        vTaskDelete(TaskHandle_push_i);
    }
}

static void control_16(void *pvParameters){
	int req = (int)pvParameters;
	int sta = handle_nvs("key16", 0, 0);
	if(req != sta){
		ESP_LOGI(TAG, "\n curr16_state %d \n", sta);
		if(req > 0){
			gpio_set_level(GPIO_NUM_16, 1);
			ESP_LOGI(TAG, "\n Turn on GPIO_NUM_16 \n");
		} else{
			gpio_set_level(GPIO_NUM_16, 0);
			ESP_LOGI(TAG, "\n Turn off GPIO_NUM_16 \n");
		}

		if(handle_nvs("key16", req, 1) == ESP_OK){
			push_listener(NULL);
//			 xTaskCreate(&push_listener, "push_listener", 8192, (void*)16, 4, &TaskHandle_push_i);
		}
	}
	vTaskDelete(TaskHandle_ctrl_16);
}

static void control_17(void *pvParameters){
	int req = (int)pvParameters;
	int sta = handle_nvs("key17", 0, 0);
	if(req != sta){
		ESP_LOGI(TAG, "\n curr17_state %d \n", sta);
		if(req > 0){
			gpio_set_level(GPIO_NUM_17, 1);
			ESP_LOGI(TAG, "\n Turn on GPIO_NUM_17 \n");
		} else{
			gpio_set_level(GPIO_NUM_17, 0);
			ESP_LOGI(TAG, "\n Turn off GPIO_NUM_17 \n");
		}

		if(handle_nvs("key17", req, 1) == ESP_OK){
			push_listener(NULL);
//			 xTaskCreate(&push_listener, "push_listener", 8192, (void*)17, 4, &TaskHandle_push_i);
		}
	}
	vTaskDelete(TaskHandle_ctrl_17);
}

static void control_18(void *pvParameters){
	int req = (int)pvParameters;
	int sta = handle_nvs("key18", 0, 0);
	if(req != sta){
		ESP_LOGI(TAG, "\n curr18_state %d \n", sta);
		if(req > 0){
			gpio_set_level(GPIO_NUM_18, 1);
			ESP_LOGI(TAG, "\n Turn on GPIO_NUM_18 \n");
		} else{
			gpio_set_level(GPIO_NUM_18, 0);
			ESP_LOGI(TAG, "\n Turn off GPIO_NUM_18 \n");
		}

		if(handle_nvs("key18", req, 1) == ESP_OK){
			push_listener(NULL);
//			 xTaskCreate(&push_listener, "push_listener", 8192, (void*)18, 4, &TaskHandle_push_i);
		}
	}
	vTaskDelete(TaskHandle_ctrl_18);
}

static void control_19(void *pvParameters){
	int req = (int)pvParameters;
	int sta = handle_nvs("key19", 0, 0);
	if(req != sta){
		ESP_LOGI(TAG, "\n curr19_state %d \n", sta);
		if(req > 0){
			gpio_set_level(GPIO_NUM_19, 1);
			ESP_LOGI(TAG, "\n Turn on GPIO_NUM_19 \n");
		} else{
			gpio_set_level(GPIO_NUM_19, 0);
			ESP_LOGI(TAG, "\n Turn off GPIO_NUM_19 \n");
		}

		if(handle_nvs("key19", req, 1) == ESP_OK){
			push_listener(NULL);
//			 xTaskCreate(&push_listener, "push_listener", 8192, (void*)19, 4, &TaskHandle_push_i);
		}
	}
	vTaskDelete(TaskHandle_ctrl_19);
}

static void push_device(){
    char buf[512];
    int ret, flags, len;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_x509_crt cacert;
    mbedtls_ssl_config conf;
    mbedtls_net_context server_fd;

    mbedtls_ssl_init(&ssl);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    ESP_LOGI(TAG, "Seeding the random number generator");

    mbedtls_ssl_config_init(&conf);

    mbedtls_entropy_init(&entropy);
    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    NULL, 0)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed returned %d", ret);
        abort();
    }

    ESP_LOGI(TAG, "Loading the CA root certificate...");

    ret = mbedtls_x509_crt_parse(&cacert, server_root_cert_pem_start,
                                 server_root_cert_pem_end-server_root_cert_pem_start);

    if(ret < 0)
    {
        ESP_LOGE(TAG, "mbedtls_x509_crt_parse returned -0x%x\n\n", -ret);
        abort();
    }

    ESP_LOGI(TAG, "Setting hostname for TLS session...");

     /* Hostname set here should match CN in server certificate */
    if((ret = mbedtls_ssl_set_hostname(&ssl, WEB_SERVER)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_set_hostname returned -0x%x", -ret);
        abort();
    }

    ESP_LOGI(TAG, "Setting up the SSL/TLS structure...");

    if((ret = mbedtls_ssl_config_defaults(&conf,
                                          MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_config_defaults returned %d", ret);
        goto exit;
    }

    /* MBEDTLS_SSL_VERIFY_OPTIONAL is bad for security, in this example it will print
       a warning if CA verification fails but it will continue to connect.
       You should consider using MBEDTLS_SSL_VERIFY_REQUIRED in your own code.
    */
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_conf_read_timeout(&conf, 3000);
#ifdef CONFIG_MBEDTLS_DEBUG
    mbedtls_esp_enable_debug_log(&conf, 4);
#endif

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_setup returned -0x%x\n\n", -ret);
        goto exit;
    }

    while(1) {
        /* Wait for the callback to set the CONNECTED_BIT in the
           event group.
        */
        xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT,
                            false, true, portMAX_DELAY);
        ESP_LOGI(TAG, "Connected to AP");

        mbedtls_net_init(&server_fd);

        ESP_LOGI(TAG, "Connecting to %s:%s...", WEB_SERVER, WEB_PORT);

        if ((ret = mbedtls_net_connect(&server_fd, WEB_SERVER,
                                      WEB_PORT, MBEDTLS_NET_PROTO_TCP)) != 0)
        {
            ESP_LOGE(TAG, "mbedtls_net_connect returned -%x", -ret);
            goto exit;
        }

        ESP_LOGI(TAG, "Connected.");

        //        mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
		mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);

        ESP_LOGI(TAG, "Performing the SSL/TLS handshake...");

        while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
        {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            {
                ESP_LOGE(TAG, "mbedtls_ssl_handshake returned -0x%x", -ret);
                goto exit;
            }
        }

        ESP_LOGI(TAG, "Verifying peer X.509 certificate...");

        if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0)
        {
            /* In real life, we probably want to close connection if ret != 0 */
            ESP_LOGW(TAG, "Failed to verify peer certificate!");
            bzero(buf, sizeof(buf));
            mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", flags);
            ESP_LOGW(TAG, "verification info: %s", buf);
        }
        else {
            ESP_LOGI(TAG, "Certificate verified.");
        }

        ESP_LOGI(TAG, "Writing HTTP request...");

        char *ip_address = "";
        tcpip_adapter_ip_info_t ip;
		memset(&ip, 0, sizeof(tcpip_adapter_ip_info_t));
		if (tcpip_adapter_get_ip_info(ESP_IF_WIFI_STA, &ip) == 0) {
			ip_address = inet_ntoa(ip.ip);
		}

        cJSON *root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "ws", (const char *)uc_pw);
        cJSON_AddStringToObject(root, "wp", (const char *)uc_pw);
		cJSON_AddStringToObject(root, "wi", ip_address);

        cJSON *gpio16 = cJSON_CreateObject();
        cJSON_AddNumberToObject(gpio16, "req", 0);
        cJSON_AddNumberToObject(gpio16, "res", 0);
        cJSON_AddNumberToObject(gpio16, "sta", 1);

        cJSON *gpio17 = cJSON_CreateObject();
        cJSON_AddNumberToObject(gpio17, "req", 0);
        cJSON_AddNumberToObject(gpio17, "res", 0);
        cJSON_AddNumberToObject(gpio17, "sta", 1);

        cJSON *gpio18 = cJSON_CreateObject();
        cJSON_AddNumberToObject(gpio18, "req", 0);
        cJSON_AddNumberToObject(gpio18, "res", 0);
        cJSON_AddNumberToObject(gpio18, "sta", 1);

        cJSON *gpio19 = cJSON_CreateObject();
        cJSON_AddNumberToObject(gpio19, "req", 0);
        cJSON_AddNumberToObject(gpio19, "res", 0);
        cJSON_AddNumberToObject(gpio19, "sta", 1);

        cJSON *pins = cJSON_CreateObject();
        cJSON_AddItemToObject(pins, "16", gpio16);
        cJSON_AddItemToObject(pins, "17", gpio17);
        cJSON_AddItemToObject(pins, "18", gpio18);
        cJSON_AddItemToObject(pins, "19", gpio19);

        cJSON_AddItemToObject(root, "ps", pins);

        uint8_t addr[6];
		esp_efuse_mac_get_default(addr);
		char mac[18];
		snprintf(mac, sizeof(mac), "%02x-%02x-%02x-%02x-%02x-%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
//		printf("%s\n", mac);

		char url[68];
		strcpy(url, WEB_URL);
		strcat( url, mac);
		strcat( url, ".json"); // access_token will be required in the future
		printf("%s\n", url);

		char *post = cJSON_Print(root);
		char len_post[10];
		snprintf(len_post, sizeof(len_post), "%d", strlen(post));

		char request[512] = "PUT ";
		strcat(request, url);
		strcat(request, " HTTP/1.0\r\n");
		strcat(request, "User-Agent: esp-idf/1.0 esp32\r\n");
		strcat(request, "Connection: close\r\n");
		strcat(request, "Host: linhomes-afa8a.firebaseio.com\r\n");
		strcat(request, "Content-Type: application/json\r\n");
		strcat(request, "Content-Length: ");
		strcat(request, len_post);
		strcat(request, "\r\n");
		strcat(request, "\r\n");
		strcat(request, post);
		REQUEST = request;
		printf("%s\n", REQUEST);
		while((ret = mbedtls_ssl_write(&ssl, (const unsigned char *)REQUEST, strlen(REQUEST))) <= 0){
			if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE){
				ESP_LOGE(TAG, "mbedtls_ssl_write returned -0x%x", -ret);
//				return;
				goto exit;
			}
		}

		len = ret;
		ESP_LOGI(TAG, "%d bytes written", len);
		ESP_LOGI(TAG, "Reading HTTP response...");
		do{
			len = sizeof(buf) - 1;
			bzero(buf, sizeof(buf));
			ret = mbedtls_ssl_read(&ssl, (unsigned char *)buf, len);

			if(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE){
				continue;
			}
			if(ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
				ret = 0;
				break;
			}
			if(ret < 0){
				ESP_LOGE(TAG, "mbedtls_ssl_read returned -0x%x", -ret);
				break;
			}
			if(ret == 0){
				ESP_LOGI(TAG, "connection closed");
				break;
			}
			mbedtls_printf("%s", buf);
		} while(1);

        mbedtls_ssl_close_notify(&ssl);

        cJSON_Delete(root);

    exit:
        mbedtls_ssl_session_reset(&ssl);
        mbedtls_net_free(&server_fd);

        if(ret != 0)
        {
            mbedtls_strerror(ret, buf, 100);
            ESP_LOGE(TAG, "Last error was: -0x%x - %s", -ret, buf);
        }
//        return;
        esp_restart();
        vTaskDelete(TaskHandle_push_d);
    }
}

void info_listener(char *buf){
//	ESP_LOGI(TAG, "\ninfo_listener----------->\n");
//	mbedtls_printf("%s", buf);
	const char needle[10] = "\r\n\r\n";
	char *response;
	response = strstr(buf, needle);
	if(response == NULL){
		response = buf;
	}
	cJSON *root = cJSON_Parse(response);
	if(root == NULL){
		ESP_LOGE(TAG, "\nNot JSON format----------->\n");
	} else{
//		tcpip_adapter_ip_info_t ip;
//		memset(&ip, 0, sizeof(tcpip_adapter_ip_info_t));
//		if (tcpip_adapter_get_ip_info(ESP_IF_WIFI_STA, &ip) == 0) {
//			char *ip_address = inet_ntoa(ip.ip);
//			cJSON_AddStringToObject(root, "wi", ip_address);
//		}
		ESP_LOGI(TAG, "type is: %d", root->type);
		if(root->type == 2){ // not found in FireBase
//			push_device();
			xTaskCreate(&push_device, "push_device", 8192, NULL, 3, &TaskHandle_push_d);
	        vTaskDelete(TaskHandle_get);
		} else{
			char *test = cJSON_Print(root);
			ESP_LOGI(TAG, "\ncJSON_Print----------->\n");
			printf("%s\n\n", test);
			cJSON *pins = cJSON_GetObjectItem(root, "ps");
			if(pins != NULL){
				cJSON *gpio16 = cJSON_GetObjectItem(pins, "16");
				if(gpio16 != NULL){
					cJSON *pin16_request = cJSON_GetObjectItem(gpio16, "req");
					if(pin16_request != NULL){
						xTaskCreate(&control_16, "control_16", 8192, (void*)pin16_request->valueint, 4, &TaskHandle_ctrl_16);
					}
				}
				cJSON *gpio17 = cJSON_GetObjectItem(pins, "17");
				if(gpio17 != NULL){
					cJSON *pin17_request = cJSON_GetObjectItem(gpio17, "req");
					if(pin17_request != NULL){
						xTaskCreate(&control_17, "control_17", 8192, (void*)pin17_request->valueint, 4, &TaskHandle_ctrl_17);
					}
				}
				cJSON *gpio18 = cJSON_GetObjectItem(pins, "18");
				if(gpio18 != NULL){
					cJSON *pin18_request = cJSON_GetObjectItem(gpio18, "req");
					if(pin18_request != NULL){
						xTaskCreate(&control_18, "control_18", 8192, (void*)pin18_request->valueint, 4, &TaskHandle_ctrl_18);
					}
				}
				cJSON *gpio19 = cJSON_GetObjectItem(pins, "18");
				if(gpio19 != NULL){
					cJSON *pin19_request = cJSON_GetObjectItem(gpio19, "req");
					if(pin19_request != NULL){
						xTaskCreate(&control_19, "control_19", 8192, (void*)pin19_request->valueint, 4, &TaskHandle_ctrl_19);
					}
				}
			}
		}
	}
	cJSON_Delete(root);
}

void task_process_WebSocket( void *pvParameters ){
    (void)pvParameters;

    //frame buffer
    WebSocket_frame_t __RX_frame;

    //create WebSocket RX Queue
    WebSocket_rx_queue = xQueueCreate(10,sizeof(WebSocket_frame_t));

    while (1){
        //receive next WebSocket frame from queue
        if(xQueueReceive(WebSocket_rx_queue,&__RX_frame, 3*portTICK_PERIOD_MS)==pdTRUE){

        	//write frame inforamtion to UART
        	printf("New Websocket frame. Length %d, payload %.*s \r\n", __RX_frame.payload_length, __RX_frame.payload_length, __RX_frame.payload);

        	cJSON *socketQ = cJSON_Parse(__RX_frame.payload);
        	if(socketQ != NULL){
        		cJSON *gpio_num = cJSON_GetObjectItem(socketQ, "ps");
        		cJSON *gpio_req = cJSON_GetObjectItem(socketQ, "req");
				if(gpio_num != NULL && gpio_req != NULL){
					switch (gpio_num->valueint){
					case 16:
						xTaskCreate(&control_16, "control_16", 8192, (void*)gpio_req->valueint, 1, &TaskHandle_ctrl_16);
						break;
					case 17:
						xTaskCreate(&control_17, "control_17", 8192, (void*)gpio_req->valueint, 1, &TaskHandle_ctrl_17);
						break;
					case 18:
						xTaskCreate(&control_18, "control_18", 8192, (void*)gpio_req->valueint, 1, &TaskHandle_ctrl_18);
						break;
					case 19:
						xTaskCreate(&control_19, "control_19", 8192, (void*)gpio_req->valueint, 1, &TaskHandle_ctrl_19);
						break;
				    default:
				        break;
					}
				}
        	}
        	//loop back frame
        	WS_write_data(__RX_frame.payload, __RX_frame.payload_length);

        	//free memory
			if (__RX_frame.payload != NULL)
				free(__RX_frame.payload);

        }
    }
}

void app_main(){
	//	gpio_set_direction(GPIO_NUM_16, GPIO_MODE_OUTPUT);
	//	gpio_set_direction(GPIO_NUM_17, GPIO_MODE_OUTPUT);
	gpio_set_direction(GPIO_NUM_18, GPIO_MODE_OUTPUT);
	//	gpio_set_direction(GPIO_NUM_19, GPIO_MODE_OUTPUT);

	esp_err_t err = nvs_flash_init();
	if (err == ESP_ERR_NVS_NO_FREE_PAGES) {
		// NVS partition was truncated and needs to be erased
		const esp_partition_t* nvs_partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS, NULL);
		assert(nvs_partition && "partition table must have an NVS partition");
		ESP_ERROR_CHECK( esp_partition_erase_range(nvs_partition, 0, nvs_partition->size) );
		// Retry nvs_flash_init
		err = nvs_flash_init();
	}

	ESP_ERROR_CHECK( err );

	int val16 = handle_nvs("key16", 0, 0);
	ESP_LOGI(TAG, "\n key16 status: %d \n", val16);
	gpio_set_level(GPIO_NUM_16, val16);
	int val17 = handle_nvs("key17", 0, 0);
	ESP_LOGI(TAG, "\n key17 status: %d \n", val17);
	gpio_set_level(GPIO_NUM_17, val17);
	int val18 = handle_nvs("key18", 0, 0);
	ESP_LOGI(TAG, "\n key18 status: %d \n", val18);
	gpio_set_level(GPIO_NUM_18, val18);
	int val19 = handle_nvs("key19", 0, 0);
	ESP_LOGI(TAG, "\n key19 status: %d \n", val19);
	gpio_set_level(GPIO_NUM_19, val19);

	gpio_set_direction(GPIO_NUM_13, GPIO_MODE_INPUT);
	gpio_set_intr_type(GPIO_NUM_13, GPIO_INTR_POSEDGE);
	gpio_evt_queue = xQueueCreate(10, sizeof(uint32_t));
	xTaskCreate(gpio_task_example, "gpio_task_example", 2048, NULL, 10, NULL);
	gpio_install_isr_service(ESP_INTR_FLAG_DEFAULT);
	gpio_isr_handler_add(GPIO_NUM_13, gpio_isr_handler, (void*) GPIO_NUM_13);

	if(handle_nvs("w_mode", 0, 0) < 1){ // neu ket noi duoc wifi truoc do thi bat mode sta
	    initialise_wifi();
	    xTaskCreate(&https_get_task, "https_get_task", 8192, NULL, 3, &TaskHandle_get); //NULL
	} else{ // neu truoc do ket noi ap that bai 10 lan thi chuyen mode
		initialise_ap();
	}

    //create WebSocker receive task
    xTaskCreate(&task_process_WebSocket, "ws_process_rx", 2048, NULL, 5, NULL);

    //Create Websocket Server Task
    xTaskCreate(&ws_server, "ws_server", 2048, NULL, 5, NULL);

}
