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

/* The examples use simple WiFi configuration that you can set via
   'make menuconfig'.
   If you'd rather not, just change the below entries to strings with
   the config you want - ie #define EXAMPLE_WIFI_SSID "mywifissid"
*/
#define EXAMPLE_WIFI_SSID "Leon A.one"//CONFIG_WIFI_SSID
#define EXAMPLE_WIFI_PASS "11330232"//CONFIG_WIFI_PASSWORD

/* FreeRTOS event group to signal when we are connected & ready to make a request */
static EventGroupHandle_t wifi_event_group;

/* The event group allows multiple bits for each event,
   but we only care about one event - are we connected
   to the AP with an IP? */
const int CONNECTED_BIT = BIT0;

/* Constants that aren't configurable in menuconfig */
#define WEB_SERVER "linhomes-afa8a.firebaseio.com"
#define WEB_PORT "443"
#define WEB_URL "/switchs/"

static const char *TAG = "example";

//char *WEB_URL = "https://linhomes-afa8a.firebaseio.com/switchs/";
char *REQUEST = "";
void info_listener(char argv[]);
void push_listener(char argv[], int state);

static const char *REQUEST2 = "PATCH /switchs/30-ae-a4-02-9e-58/pins/18/.json HTTP/1.1\r\n"
    "Host: linhomes-afa8a.firebaseio.com\r\n"
	"Content-Type: application/x-www-form-urlencoded\r\n"
	"Cache-Control: no-cache\r\n"
    "Postman-Token: b0d1bcc1-6e98-9e4a-b1d5-dd30a367d52d\r\n"
	"{\"response\":0}";

/* Root cert for howsmyssl.com, taken from server_root_cert.pem
   The PEM file was extracted from the output of this command:
   openssl s_client -showcerts -connect www.howsmyssl.com:443 </dev/null
   The CA root cert is the last cert given in the chain of certs.
   To embed it in the app binary, the PEM file is named
   in the component.mk COMPONENT_EMBED_TXTFILES variable.
*/
//extern const uint8_t server_root_cert_pem_start[] asm("_binary_server_root_cert_pem_start");
//extern const uint8_t server_root_cert_pem_end[]   asm("_binary_server_root_cert_pem_end");

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
    int ret, len;
    char buf[512];

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
//
    mbedtls_entropy_init(&entropy);
    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0){
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed returned %d", ret);
        abort();
    }
//
//    ESP_LOGI(TAG, "Setting up the SSL/TLS structure...");
    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if((ret) != 0){
        ESP_LOGE(TAG, "mbedtls_ssl_config_defaults returned %d", ret);
        goto exit;
    }

    /* MBEDTLS_SSL_VERIFY_OPTIONAL is bad for security, in this example it will print
       a warning if CA verification fails but it will continue to connect.
       You should consider using MBEDTLS_SSL_VERIFY_REQUIRED in your own code.
    */
//    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	#ifdef CONFIG_MBEDTLS_DEBUG
//		mbedtls_esp_enable_debug_log(&conf, 4);
	#endif

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0){
        ESP_LOGE(TAG, "mbedtls_ssl_setup returned -0x%x\n\n", -ret);
        goto exit;
    }

    while(1) {
        /* Wait for the callback to set the CONNECTED_BIT in the
           event group.
        */
        xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT, false, true, portMAX_DELAY);
//        ESP_LOGI(TAG, "Connected to AP");

        mbedtls_net_init(&server_fd);

        ESP_LOGI(TAG, "Connecting to %s:%s...", WEB_SERVER, WEB_PORT);

        if ((ret = mbedtls_net_connect(&server_fd, WEB_SERVER, WEB_PORT, MBEDTLS_NET_PROTO_TCP)) != 0){
            ESP_LOGE(TAG, "mbedtls_net_connect returned -%x", -ret);
            goto exit;
        }

//        ESP_LOGI(TAG, "Connected.");
//
        mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

//        ESP_LOGI(TAG, "Writing HTTP request...");
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
		strcat(request, " HTTP/1.1\r\n");
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
		} while(1);

        mbedtls_ssl_close_notify(&ssl);

    exit:
        mbedtls_ssl_session_reset(&ssl);
        mbedtls_net_free(&server_fd);

        if(ret != 0){
            mbedtls_strerror(ret, buf, 100);
            ESP_LOGE(TAG, "Last error was: -0x%x - %s", -ret, buf);
        }

        for(int countdown = 1; countdown > 0; countdown--) {
            ESP_LOGI(TAG, "%d...", countdown);
            vTaskDelay(1000 / portTICK_PERIOD_MS);
        }
        ESP_LOGI(TAG, "Starting again!");
        vTaskDelete(NULL);
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
		tcpip_adapter_ip_info_t ip;
		memset(&ip, 0, sizeof(tcpip_adapter_ip_info_t));
		if (tcpip_adapter_get_ip_info(ESP_IF_WIFI_STA, &ip) == 0) {
			char *ip_address = inet_ntoa(ip.ip);
			cJSON_AddStringToObject(root, "wifi_ip", ip_address);
		}
//		ESP_LOGI(TAG, "type is: %d", root->type);
		char *test = cJSON_Print(root);
		ESP_LOGI(TAG, "\ncJSON_Print----------->\n");
		printf("%s\n\n", test);
		cJSON *pins = cJSON_GetObjectItem(root, "pins");
		if(pins != NULL){
			test = cJSON_Print(pins);
			printf("%s\n\n", test);
			cJSON *gpio18 = cJSON_GetObjectItem(pins, "18");
			if(gpio18 != NULL){
				test = cJSON_Print(gpio18);
				printf("%s\n\n", test);
				printf("request: %d\n", cJSON_GetObjectItem(gpio18, "request")->valueint);
				printf("response: %d\n", cJSON_GetObjectItem(gpio18, "response")->valueint);
				printf("state: %d\n", cJSON_GetObjectItem(gpio18, "state")->valueint);

				int request = cJSON_GetObjectItem(gpio18, "request")->valueint;
				int state = 1;
				if(state != request){
					uint8_t addr[6];
					esp_efuse_mac_get_default(addr);
					char mac[18];
					snprintf(mac, sizeof(mac), "%02x-%02x-%02x-%02x-%02x-%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
					char url[68];
					strcpy(url, WEB_URL);
					strcat( url, mac);
					strcat( url, "/pins/18/.json");
					printf("%s\n", url);
					push_listener(url, request);
				}
			}
		}
	}
	cJSON_Delete(root);
}

void push_listener(char *url, int state){
    int ret, len;
    char buf[512];

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
//
    mbedtls_entropy_init(&entropy);
    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0){
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed returned %d", ret);
        abort();
    }
//
//    ESP_LOGI(TAG, "Setting up the SSL/TLS structure...");
    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if((ret) != 0){
        ESP_LOGE(TAG, "mbedtls_ssl_config_defaults returned %d", ret);
        goto exit;
    }

    /* MBEDTLS_SSL_VERIFY_OPTIONAL is bad for security, in this example it will print
       a warning if CA verification fails but it will continue to connect.
       You should consider using MBEDTLS_SSL_VERIFY_REQUIRED in your own code.
    */
//    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	#ifdef CONFIG_MBEDTLS_DEBUG
//		mbedtls_esp_enable_debug_log(&conf, 4);
	#endif

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0){
        ESP_LOGE(TAG, "mbedtls_ssl_setup returned -0x%x\n\n", -ret);
        goto exit;
    }

    while(1) {
        /* Wait for the callback to set the CONNECTED_BIT in the
           event group.
        */
        xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT, false, true, portMAX_DELAY);
//        ESP_LOGI(TAG, "Connected to AP");

        mbedtls_net_init(&server_fd);

        ESP_LOGI(TAG, "Connecting to %s:%s...", WEB_SERVER, WEB_PORT);

        if ((ret = mbedtls_net_connect(&server_fd, WEB_SERVER, WEB_PORT, MBEDTLS_NET_PROTO_TCP)) != 0){
            ESP_LOGE(TAG, "mbedtls_net_connect returned -%x", -ret);
            goto exit;
        }

//        ESP_LOGI(TAG, "Connected.");
//
        mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

//        ESP_LOGI(TAG, "Writing HTTP request...");
        uint8_t addr[6];
		esp_efuse_mac_get_default(addr);
		char mac[18];
		snprintf(mac, sizeof(mac), "%02x-%02x-%02x-%02x-%02x-%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
//		printf("%s\n", mac);

		char data[20];
		snprintf(data, sizeof(data), "{\"response\":%d}", state);
		char *post = data;
		char len_post[10];
		snprintf(len_post, sizeof(len_post), "%d", sizeof(data) + 1);

		char request[300] = "PATCH ";
		strcat(request, url);
		strcat(request, " HTTP/1.1CRLF");
		strcat(request, "Host: linhomes-afa8a.firebaseio.comCRLF");
//		strcat(request, "User-Agent: esp-idf/1.0 esp32\r\n");
//		strcat(request, "Accept: application/json\r\n");
//		strcat(request, "Content-Type: application/x-www-form-urlencoded\n");
//		strcat(request, "Content-Length: 15\r\n");
//		strcat(request, len_post);
		//		strcat(request, "\r\n");
		strcat(request, "Cache-Control: no-cacheCRLF");
		strcat(request, "CRLF");
		strcat(request, "'{\"response\":0}'");
//		strcat(request, "\r\n");
		REQUEST = request;

		printf("%s\n", REQUEST2);
		while((ret = mbedtls_ssl_write(&ssl, (const unsigned char *)REQUEST2, strlen(REQUEST2))) <= 0){
			if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE){
				ESP_LOGE(TAG, "mbedtls_ssl_write returned -0x%x", -ret);
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
//			printf("%s", buf);

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

    exit:
        mbedtls_ssl_session_reset(&ssl);
        mbedtls_net_free(&server_fd);

        if(ret != 0){
            mbedtls_strerror(ret, buf, 100);
            ESP_LOGE(TAG, "Last error was: -0x%x - %s", -ret, buf);
        }

        for(int countdown = 1; countdown > 0; countdown--) {
            ESP_LOGI(TAG, "%d...", countdown);
            vTaskDelay(1000 / portTICK_PERIOD_MS);
        }
        ESP_LOGI(TAG, "Starting again!");
        vTaskDelete(NULL);
    }
}

void app_main(){
    ESP_ERROR_CHECK( nvs_flash_init() );
    initialise_wifi();
    xTaskCreate(&https_get_task, "https_get_task", 8192, NULL, 5, NULL);
}
