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
#include "driver/ledc.h"
//#include "freertos/queue.h"
#include "driver/gpio.h"

/* The examples use simple WiFi configuration that you can set via
   'make menuconfig'.
   If you'd rather not, just change the below entries to strings with
   the config you want - ie #define EXAMPLE_WIFI_SSID "mywifissid"
*/
#define EXAMPLE_WIFI_SSID "Leon A.one"//CONFIG_WIFI_SSID MOBILE STAR WiFi
#define EXAMPLE_WIFI_PASS "11330232"//CONFIG_WIFI_PASSWORD mobiist@r2017

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

#define GPIO_INPUT_IO_0    18
#define GPIO_OUTPUT_PIN_SEL  ((1<<GPIO_INPUT_IO_0))
#define ESP_INTR_FLAG_DEFAULT 0

gpio_num_t pin_nums;

static const char *TAG = "example";

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
void push_listener(char argv[], int state);
void push_device();

/* Root cert for howsmyssl.com, taken from server_root_cert.pem
   The PEM file was extracted from the output of this command:
   openssl s_client -showcerts -connect www.howsmyssl.com:443 </dev/null
   The CA root cert is the last cert given in the chain of certs.
   To embed it in the app binary, the PEM file is named
   in the component.mk COMPONENT_EMBED_TXTFILES variable.
*/
extern const uint8_t server_root_cert_pem_start[] asm("_binary_server_root_cert_pem_start");
extern const uint8_t server_root_cert_pem_end[]   asm("_binary_server_root_cert_pem_end");

static xQueueHandle gpio_evt_queue = NULL;

static void IRAM_ATTR gpio_isr_handler(void* arg){
    uint32_t gpio_num = (uint32_t) arg;
    xQueueSendFromISR(gpio_evt_queue, &gpio_num, NULL);
}

static void gpio_task_example(void* arg){
    uint32_t io_num;
    for(;;) {
        if(xQueueReceive(gpio_evt_queue, &io_num, portMAX_DELAY)) {
            printf("GPIO[%d] intr, val: %d\n", io_num, gpio_get_level(io_num));
        }
    }
}

static esp_err_t event_handler(void *ctx, system_event_t *event){
    switch(event->event_id) {
    case SYSTEM_EVENT_STA_START:
        esp_wifi_connect();
        break;
    case SYSTEM_EVENT_STA_GOT_IP:
        xEventGroupSetBits(wifi_event_group, CONNECTED_BIT);
        break;
    case SYSTEM_EVENT_STA_DISCONNECTED:
        /* This is a workaround as ESP32 WiFi libs don't currently
           auto-reassociate. */
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
    wifi_config_t wifi_config = {
        .sta = {
            .ssid = EXAMPLE_WIFI_SSID,
            .password = EXAMPLE_WIFI_PASS,
        },
    };
    ESP_LOGI(TAG, "Setting WiFi configuration SSID %s...", wifi_config.sta.ssid);
    ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK( esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config) );
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

        mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

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
		REQUEST = request;
		printf("%s\n", REQUEST);
		while((ret = mbedtls_ssl_write(&ssl, (const unsigned char *)REQUEST, strlen(REQUEST))) <= 0){
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

        for(int countdown = 2; countdown >= 0; countdown--) {
            ESP_LOGI(TAG, "%d...", countdown);
            vTaskDelay(1000 / portTICK_PERIOD_MS);
        }
        ESP_LOGI(TAG, "Starting again!");
        vTaskDelete(NULL);
    }
}

void push_listener(char *url, int state){
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

        mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

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
//		strcat(request, "Content-Length: 14");
		strcat(request, "Content-Length: ");
		strcat(request, len_post);
		strcat(request, "\r\n");
		strcat(request, "\r\n");
//		strcat(request, "{\"pwr\":\"off\"}");
		strcat(request, post);
//		strcat(request, "\r\n");
		REQUEST = request;

//		char *REQUEST2 = "PUT " WEB_URL " HTTP/1.0\r\n"
//		"User-Agent: esp-idf/1.0 esp32\r\n"
//		"Connection: close\r\n" //general header
//		"Host: "WEB_SERVER"\r\n" //request header
//		"Content-Type: application/json\r\n" //entity header
//		"Content-Length: 13\r\n" //entity header
//		"\r\n"
//		"{\"pwr\":\"off\"}";

		printf("%s\n", REQUEST);
		while((ret = mbedtls_ssl_write(&ssl, (const unsigned char *)REQUEST, strlen(REQUEST))) <= 0){
			if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE){
				ESP_LOGE(TAG, "mbedtls_ssl_write returned -0x%x", -ret);
//				goto exit;
				return;
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

        if(ret != 0)
        {
            mbedtls_strerror(ret, buf, 100);
            ESP_LOGE(TAG, "Last error was: -0x%x - %s", -ret, buf);
        }
        return;

//        for(int countdown = 10; countdown >= 0; countdown--) {
//            ESP_LOGI(TAG, "%d...", countdown);
//            vTaskDelay(1000 / portTICK_PERIOD_MS);
//        }
//        ESP_LOGI(TAG, "Starting again!");
//        vTaskDelete(NULL);
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
			xTaskCreate(&push_device, "push_device", 8192, NULL, 5, NULL);
		} else{
			char *test = cJSON_Print(root);
			ESP_LOGI(TAG, "\ncJSON_Print----------->\n");
			printf("%s\n\n", test);
			cJSON *pins = cJSON_GetObjectItem(root, "ps");
			if(pins != NULL){
				cJSON *gpio16 = cJSON_GetObjectItem(pins, "16");
				if(gpio16 != NULL){
					cJSON *pin16_request = cJSON_GetObjectItem(gpio16, "req");
					cJSON *pin16_response = cJSON_GetObjectItem(gpio16, "res");
					cJSON *pin16_state = cJSON_GetObjectItem(gpio16, "sta");
					if(pin16_request != NULL && pin16_response != NULL && pin16_state != NULL){
						if((pin16_request->valueint != pin16_response->valueint) || pin16_state->valueint != 1){
							if(pin16_request->valueint > 0){
								gpio_set_level(GPIO_NUM_16, 1);
								ESP_LOGI(TAG, "\n Turn on GPIO_NUM_16 \n");
							} else{
								gpio_set_level(GPIO_NUM_16, 0);
								ESP_LOGI(TAG, "\n Turn off GPIO_NUM_16 \n");
							}
							uint8_t addr[6];
							esp_efuse_mac_get_default(addr);
							char mac[18];
							snprintf(mac, sizeof(mac), "%02x-%02x-%02x-%02x-%02x-%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
							char url[68];
							strcpy(url, WEB_URL);
							strcat( url, mac);
							strcat( url, "/ps/16/.json");
							printf("%s\n", url);
							push_listener(url, pin16_request->valueint);
						}
					}
				}
				cJSON *gpio17 = cJSON_GetObjectItem(pins, "17");
				if(gpio17 != NULL){
					cJSON *gpio17_request = cJSON_GetObjectItem(gpio17, "req");
					cJSON *gpio17_response = cJSON_GetObjectItem(gpio17, "res");
					cJSON *gpio17_state = cJSON_GetObjectItem(gpio17, "sta");
					if(gpio17_request != NULL && gpio17_response != NULL && gpio17_state != NULL){
						if((gpio17_request->valueint != gpio17_response->valueint) || gpio17_state->valueint != 1){
							if(gpio17_request->valueint > 0){
								gpio_set_level(GPIO_NUM_17, 1);
								ESP_LOGI(TAG, "\n Turn on GPIO_NUM_17 \n");
							} else{
								gpio_set_level(GPIO_NUM_17, 0);
								ESP_LOGI(TAG, "\n Turn off GPIO_NUM_17 \n");
							}
							uint8_t addr[6];
							esp_efuse_mac_get_default(addr);
							char mac[18];
							snprintf(mac, sizeof(mac), "%02x-%02x-%02x-%02x-%02x-%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
							char url[68];
							strcpy(url, WEB_URL);
							strcat( url, mac);
							strcat( url, "/ps/17/.json");
							printf("%s\n", url);
							push_listener(url, gpio17_request->valueint);
						}
					}
				}
				cJSON *gpio18 = cJSON_GetObjectItem(pins, "18");
				if(gpio18 != NULL){
					cJSON *pin18_request = cJSON_GetObjectItem(gpio18, "req");
					cJSON *pin18_response = cJSON_GetObjectItem(gpio18, "res");
					cJSON *pin18_state = cJSON_GetObjectItem(gpio18, "sta");
					if(pin18_request != NULL && pin18_response != NULL && pin18_state != NULL){
						if((pin18_request->valueint != pin18_response->valueint) || pin18_state->valueint != 1){
							if(pin18_request->valueint > 0){
								gpio_set_level(GPIO_NUM_18, 1);
								ESP_LOGI(TAG, "\n Turn on GPIO_NUM_18 \n");
							} else{
								gpio_set_level(GPIO_NUM_18, 0);
								ESP_LOGI(TAG, "\n Turn off GPIO_NUM_18 \n");
							}
							uint8_t addr[6];
							esp_efuse_mac_get_default(addr);
							char mac[18];
							snprintf(mac, sizeof(mac), "%02x-%02x-%02x-%02x-%02x-%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
							char url[68];
							strcpy(url, WEB_URL);
							strcat( url, mac);
							strcat( url, "/ps/18/.json");
							printf("%s\n", url);
							push_listener(url, pin18_request->valueint);
						}
					}
				}
				cJSON *gpio19 = cJSON_GetObjectItem(pins, "19");
				if(gpio19 != NULL){
					cJSON *gpio19_request = cJSON_GetObjectItem(gpio19, "req");
					cJSON *gpio19_response = cJSON_GetObjectItem(gpio19, "res");
					cJSON *gpio19_state = cJSON_GetObjectItem(gpio19, "sta");
					if(gpio19_request != NULL && gpio19_response != NULL && gpio19_state != NULL){
						if((gpio19_request->valueint != gpio19_response->valueint) || gpio19_state->valueint != 1){
							if(gpio19_request->valueint > 0){
								gpio_set_level(GPIO_NUM_19, 1);
								ESP_LOGI(TAG, "\n Turn on GPIO_NUM_19 \n");
							} else{
								gpio_set_level(GPIO_NUM_19, 0);
								ESP_LOGI(TAG, "\n Turn off GPIO_NUM_19 \n");
							}
							uint8_t addr[6];
							esp_efuse_mac_get_default(addr);
							char mac[18];
							snprintf(mac, sizeof(mac), "%02x-%02x-%02x-%02x-%02x-%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
							char url[68];
							strcpy(url, WEB_URL);
							strcat( url, mac);
							strcat( url, "/ps/19/.json");
							printf("%s\n", url);
							push_listener(url, gpio19_request->valueint);
						}
					}
				}
			}
		}
	}
	cJSON_Delete(root);
}

void push_device(){
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

        mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

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
        cJSON_AddStringToObject(root, "ws", EXAMPLE_WIFI_SSID);
        cJSON_AddStringToObject(root, "wp", EXAMPLE_WIFI_PASS);
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
        vTaskDelete(NULL);
    }
}

void app_main(){
    ESP_ERROR_CHECK( nvs_flash_init() );
    initialise_wifi();
    xTaskCreate(&https_get_task, "https_get_task", 8192, NULL, 5, NULL);

    gpio_config_t io_conf;
	//disable interrupt
	io_conf.intr_type = GPIO_PIN_INTR_ANYEGDE;
	//set as output mode
	io_conf.mode = GPIO_MODE_OUTPUT;
	//bit mask of the pins that you want to set,e.g.GPIO18/19
	io_conf.pin_bit_mask = GPIO_OUTPUT_PIN_SEL;
	//disable pull-down mode
	io_conf.pull_down_en = 1;
	//disable pull-up mode
	io_conf.pull_up_en = 1;
	//configure GPIO with the given settings
	gpio_config(&io_conf);

	//change gpio intrrupt type for one pin
	gpio_set_intr_type(GPIO_NUM_18, GPIO_INTR_ANYEDGE);

	//create a queue to handle gpio event from isr
	gpio_evt_queue = xQueueCreate(10, sizeof(uint32_t));
	//start gpio task
	xTaskCreate(gpio_task_example, "gpio_task_example", 2048, NULL, 10, NULL);

	//install gpio isr service
	gpio_install_isr_service(ESP_INTR_FLAG_DEFAULT);
	//hook isr handler for specific gpio pin
	gpio_isr_handler_add(GPIO_NUM_18, gpio_isr_handler, (void*) GPIO_NUM_18);

//	gpio_set_level(GPIO_NUM_18, 1);
//
//	int state = gpio_get_level(GPIO_NUM_18);
//	ESP_LOGW(TAG, "\n GPIO18: %d \n", state);

}
