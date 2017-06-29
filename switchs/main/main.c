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
char uc_mac[18] = "";
unsigned char uc_ssid[32] = "";
unsigned char uc_pw[64] = "";
char uc_ip[16] = "";

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

static const char *TAG = "switch";
int handshake_ws = 0;
int pin_state = -1;
bool rebuild_get = false; // tracking vTask was deleted
bool pushing = false;

char *REQUEST = "";
void info_listener(char argv[]);

xTaskHandle TaskHandle_ws;
xTaskHandle TaskHandle_get;
xTaskHandle TaskHandle_push_i;
xTaskHandle TaskHandle_repair;
xTaskHandle TaskHandle_push_d;
xTaskHandle TaskHandle_ctrl_18;

//WebSocket_frame_f __ws_frame_f;
//WebSocket_frame_t __RX_frame;

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
		if(flag == 1){ // Write
			err = nvs_set_i32(my_handle, key, val);
			ESP_LOGW(TAG, "\n write %s = %d => %s \n", key, val, ((err != ESP_OK) ? "Failed!\n" : "Done\n"));
			err = nvs_commit(my_handle);
			status = err;
		} else{ // Read
			err = nvs_get_i32(my_handle, key, &status);
			switch (err) {
				case ESP_OK:
					ESP_LOGW(TAG, "Read key %s = %d\n", key, status);
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

static void handle_snvs(const char *key, char *val, int flag){
	esp_err_t err;
	nvs_handle my_handle;
	err = nvs_open("storage", NVS_READWRITE, &my_handle);
	if (err != ESP_OK) {
		printf("Error (%d) opening NVS handle!\n", err);
	} else {
		printf("Done\n");
		// Write
		if(flag == 1){
			// Write
			err = nvs_set_str(my_handle, key, val);
			err = nvs_commit(my_handle);
//			printf((err != ESP_OK) ? "Failed!\n" : "Done\n");
			ESP_LOGW(TAG, "\n write %s = %s => %s \n", key, val, ((err != ESP_OK) ? "Failed!\n" : "Done\n"));
		} else{ // Read
			size_t size = 32;
			malloc(size);
			err = nvs_get_str(my_handle, key, val, &size);
			ESP_LOGW(TAG, "\n read %s = %s => %s \n", key, val, ((err != ESP_OK) ? "Failed!\n" : "Done\n"));
			switch (err) {
				case ESP_OK:
					printf("NVS read\n");
					ESP_LOGW(TAG, "Read key %s = %s\n", key, val);
					break;
				case ESP_ERR_NVS_NOT_FOUND:
					printf("The value is not initialized yet!\n");
					break;
				case ESP_ERR_NVS_INVALID_HANDLE:
					printf("ESP_ERR_NVS_INVALID_HANDLE %d!\n", err);
					break;
				case ESP_ERR_NVS_INVALID_NAME:
					printf("ESP_ERR_NVS_INVALID_NAME %d!\n", err);
					break;
				case ESP_ERR_NVS_INVALID_LENGTH:
					printf("ESP_ERR_NVS_INVALID_LENGTH %d!\n", err);
					break;
				default :
					printf("Error (%d) reading!\n", err);
			}
		}

		// Close
		nvs_close(my_handle);
	}
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
            if(io_num == GPIO_NUM_14){
            	if(handle_nvs("w_mode", 1, 1) == ESP_OK){ // keo chan 13 len cao thi switch sang mode ap
            		const esp_partition_t* nvs_partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS, NULL);
					assert(nvs_partition && "partition table must have an NVS partition");
					ESP_ERROR_CHECK( esp_partition_erase_range(nvs_partition, 0, nvs_partition->size) );
            		gpio_isr_handler_remove(GPIO_NUM_14);
            	    vTaskDelay(1000 / portTICK_PERIOD_MS);
					esp_restart();
            		vTaskDelete(NULL);
				}
            }
        }
    }
}

static void push_device(){
    char buf[512];
    int ret, flags, len;
    pushing = true;
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
    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0) {
    	pushing = false;
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed returned %d", ret);
        abort();
    }

    ESP_LOGI(TAG, "Loading the CA root certificate...");

    ret = mbedtls_x509_crt_parse(&cacert, server_root_cert_pem_start, server_root_cert_pem_end-server_root_cert_pem_start);

    if(ret < 0){
    	pushing = false;
        ESP_LOGE(TAG, "mbedtls_x509_crt_parse returned -0x%x\n\n", -ret);
        abort();
    }

    ESP_LOGI(TAG, "Setting hostname for TLS session...");

//     Hostname set here should match CN in server certificate
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

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_conf_read_timeout(&conf, 9000);
#ifdef CONFIG_MBEDTLS_DEBUG
    mbedtls_esp_enable_debug_log(&conf, 4);
#endif

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0){
        ESP_LOGE(TAG, "mbedtls_ssl_setup returned -0x%x\n\n", -ret);
        goto exit;
    }

    while(1) {
        xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT,
                            false, true, portMAX_DELAY);
        ESP_LOGI(TAG, "Connected to AP");

        mbedtls_net_init(&server_fd);

        ESP_LOGI(TAG, "Connecting to %s:%s...", WEB_SERVER, WEB_PORT);

        if ((ret = mbedtls_net_connect(&server_fd, WEB_SERVER, WEB_PORT, MBEDTLS_NET_PROTO_TCP)) != 0){
            ESP_LOGE(TAG, "mbedtls_net_connect returned -%x", -ret);
            goto exit;
        }

        ESP_LOGI(TAG, "Connected.");

        //        mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
		mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);

        ESP_LOGI(TAG, "Performing the SSL/TLS handshake...");

        while ((ret = mbedtls_ssl_handshake(&ssl)) != 0){
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE){
                ESP_LOGE(TAG, "mbedtls_ssl_handshake returned -0x%x", -ret);
                goto exit;
            }
        }

        ESP_LOGI(TAG, "Verifying peer X.509 certificate...");

        if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0){
            ESP_LOGW(TAG, "Failed to verify peer certificate!");
            bzero(buf, sizeof(buf));
            mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", flags);
            ESP_LOGW(TAG, "verification info: %s", buf);
        } else {
            ESP_LOGI(TAG, "Certificate verified.");
        }

        ESP_LOGI(TAG, "Writing HTTP request...");
        char *ip_address = "";
        tcpip_adapter_ip_info_t ip;
		memset(&ip, 0, sizeof(tcpip_adapter_ip_info_t));
		if (tcpip_adapter_get_ip_info(ESP_IF_WIFI_STA, &ip) == 0) {
			ip_address = inet_ntoa(ip.ip);
			snprintf(uc_ip, sizeof(uc_ip), "%s", ip_address);
		}

        cJSON *root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "ws", (const char *)uc_ssid);
        cJSON_AddStringToObject(root, "wp", (const char *)uc_pw);
		cJSON_AddStringToObject(root, "wi", ip_address);
//		cJSON_AddStringToObject(root, "mac", mac);

        cJSON *gpio18 = cJSON_CreateObject();
        cJSON_AddNumberToObject(gpio18, "req", 0);
//        cJSON_AddNumberToObject(gpio18, "res", 0);
//        cJSON_AddNumberToObject(gpio18, "sta", 1);

        cJSON *pins = cJSON_CreateObject();
        cJSON_AddItemToObject(pins, "18", gpio18);

        cJSON_AddItemToObject(root, "ps", pins);

		char url[68];
		strcpy(url, WEB_URL);
		strcat( url, uc_mac);
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

        if(ret != 0){
            mbedtls_strerror(ret, buf, 100);
            ESP_LOGE(TAG, "Last error was: -0x%x - %s", -ret, buf);
        	pushing = true;
        } else{
        	pushing = false;
        }
        vTaskDelete(TaskHandle_push_d);
    }
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
    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0) {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed returned %d", ret);
        abort();
    }

    ESP_LOGI(TAG, "Loading the CA root certificate...");

    ret = mbedtls_x509_crt_parse(&cacert, server_root_cert_pem_start, server_root_cert_pem_end-server_root_cert_pem_start);

    if(ret < 0) {
        ESP_LOGE(TAG, "mbedtls_x509_crt_parse returned -0x%x\n\n", -ret);
        abort();
    }

    ESP_LOGI(TAG, "Setting hostname for TLS session...");

    if((ret = mbedtls_ssl_set_hostname(&ssl, WEB_SERVER)) != 0) {
        ESP_LOGE(TAG, "mbedtls_ssl_set_hostname returned -0x%x", -ret);
        abort();
    }

    ESP_LOGI(TAG, "Setting up the SSL/TLS structure...");

	mbedtls_ssl_conf_read_timeout(&conf, 9000);
    if((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
		MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0 ) {
    	ESP_LOGE(TAG, "mbedtls_ssl_config_defaults returned %d", ret);
        goto exit;
    }

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
#ifdef CONFIG_MBEDTLS_DEBUG
    mbedtls_esp_enable_debug_log(&conf, 4);
#endif

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        ESP_LOGE(TAG, "mbedtls_ssl_setup returned -0x%x\n\n", -ret);
        goto exit;
    }

    while(1) {
        xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT, false, true, portMAX_DELAY);
        if(ws_check_client() > 0){ // request via socket, not network
			goto exit;
        }
        handshake_ws = 0;
        ESP_LOGI(TAG, "Connected to AP");

        char *ip_address = "";
		tcpip_adapter_ip_info_t ip;
		memset(&ip, 0, sizeof(tcpip_adapter_ip_info_t));
		if (tcpip_adapter_get_ip_info(ESP_IF_WIFI_STA, &ip) == 0) {
			ip_address = inet_ntoa(ip.ip);
			snprintf(uc_ip, sizeof(uc_ip), "%s", ip_address);
		}
        printf("Socket connected: %d\n", 0);

        mbedtls_net_init(&server_fd);

        ESP_LOGI(TAG, "Connecting to %s:%s...", WEB_SERVER, WEB_PORT);

        if ((ret = mbedtls_net_connect(&server_fd, WEB_SERVER, WEB_PORT, MBEDTLS_NET_PROTO_TCP)) != 0){
            ESP_LOGE(TAG, "mbedtls_net_connect returned -%x", -ret);
            goto exit;
        }

        ESP_LOGI(TAG, "Connected.");

//        mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
        mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);

        ESP_LOGI(TAG, "Performing the SSL/TLS handshake...");
        while ((ret = mbedtls_ssl_handshake(&ssl)) != 0){
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE){
                ESP_LOGE(TAG, "mbedtls_ssl_handshake returned -0x%x", -ret);
                goto exit;
            }
        }

        ESP_LOGI(TAG, "Verifying peer X.509 certificate...");

        if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0){
            /* In real life, we probably want to close connection if ret != 0 */
            ESP_LOGW(TAG, "Failed to verify peer certificate!");
            bzero(buf, sizeof(buf));
            mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", flags);
            ESP_LOGW(TAG, "verification info: %s", buf);
        } else {
            ESP_LOGI(TAG, "Certificate verified.");
        }

        ESP_LOGI(TAG, "Writing HTTP request...");

        char url[68];
		strcpy(url, WEB_URL);
		strcat( url, uc_mac);
		strcat( url, "/ps/18.json"); // access_token will be required in the future
		printf("%s\n", url);

		char request[120] = "GET ";
		strcat(request, url);
		strcat(request, " HTTP/1.0\r\n");
		strcat(request, "User-Agent: esp-idf/1.0 esp32\r\n");
		strcat(request, "Connection: close\r\n");
		strcat(request, "Host: linhomes-afa8a.firebaseio.com\r\n");
		strcat(request, "User-Agent: esp-idf/1.0 esp32\r\n");
		strcat(request, "Accept: application/json\r\n");
		strcat(request, "\r\n");

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
		char final_buf[512] = "";
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
			strcat(final_buf, buf);
		} while(1);
		info_listener(final_buf);

        mbedtls_ssl_close_notify(&ssl);

	exit:
		mbedtls_ssl_session_reset(&ssl);
		mbedtls_net_free(&server_fd);

		if(ret != 0) {
			mbedtls_strerror(ret, buf, 100);
			if(ws_check_client() < 1){
				ESP_LOGE(TAG, "Last error was: -0x%x - %s", -ret, buf);
			}
		}
    }
}

static esp_err_t event_handler(void *ctx, system_event_t *event){
	ESP_LOGI(TAG, "\n error id: %d \n", event->event_id);
    switch(event->event_id) {
        case SYSTEM_EVENT_STA_START:{
            esp_wifi_connect();
            break;
        }
        case SYSTEM_EVENT_STA_DISCONNECTED:{
            esp_wifi_connect();
            xEventGroupClearBits(wifi_event_group, CONNECTED_BIT);
            break;
        }
        case SYSTEM_EVENT_STA_CONNECTED:{
        	char *ip_address = "";
			tcpip_adapter_ip_info_t ip;
			memset(&ip, 0, sizeof(tcpip_adapter_ip_info_t));
			if (tcpip_adapter_get_ip_info(ESP_IF_WIFI_STA, &ip) == 0) {
				ip_address = inet_ntoa(ip.ip);
			}
        	handle_snvs("wi", ip_address, 1);
        	break;
        }
        case SYSTEM_EVENT_STA_GOT_IP:{
        	ESP_LOGI(TAG, "got ip:%s\n",
    		ip4addr_ntoa(&event->event_info.got_ip.ip_info.ip));
        	xEventGroupSetBits(wifi_event_group, CONNECTED_BIT);
            break;
        }
        case SYSTEM_EVENT_AP_STACONNECTED:{
        	ESP_LOGI(TAG, "station:"MACSTR" join,AID=%d\n",
    		MAC2STR(event->event_info.sta_connected.mac),
    		event->event_info.sta_connected.aid);
        	xEventGroupSetBits(wifi_event_group, CONNECTED_BIT);
        	break;
        }
        case SYSTEM_EVENT_AP_STADISCONNECTED:{
        	ESP_LOGI(TAG, "station:"MACSTR"leave,AID=%d\n",
    		MAC2STR(event->event_info.sta_disconnected.mac),
    		event->event_info.sta_disconnected.aid);
        	xEventGroupClearBits(wifi_event_group, CONNECTED_BIT);
        	break;
        }
        default: break;
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
    	.ssid = "MOBILE STAR WiFi",
		.password = "mobiist@r2017"
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
	wifi_event_group = xEventGroupCreate();

	    tcpip_adapter_init();
	    ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));

	    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
	    wifi_config_t wifi_config = {
	        .ap = {
	            .ssid = "Leon ESP32",
	            .ssid_len = 0,
	            .max_connection=2,
	            .password = "11330232",
	            .authmode = WIFI_AUTH_WPA_WPA2_PSK
	        },
	    };


        uint8_t addr[6];
		esp_efuse_mac_get_default(addr);
		char mac[32];
		snprintf(mac, sizeof(mac), "Switch-%02x%02x%02x%02x%02x%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	    memcpy(wifi_config.ap.ssid, mac, sizeof(mac));

	    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
	    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_AP, &wifi_config));
	    ESP_ERROR_CHECK(esp_wifi_start());

	    ESP_LOGI(TAG, "wifi_init_softap finished\n");
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

//     MBEDTLS_SSL_VERIFY_OPTIONAL is bad for security, in this example it will print
//       a warning if CA verification fails but it will continue to connect.
//       You should consider using MBEDTLS_SSL_VERIFY_REQUIRED in your own code.

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

static void control_18(void *pvParameters){
	int req = (int)pvParameters;
	if(pin_state == -1){
		int sta = handle_nvs("key18", 0, 0);
		pin_state = sta;
	}
	if(req != pin_state){
		ESP_LOGI(TAG, "\n curr18_state %d \n", pin_state);
		if(req > 0){
			gpio_set_level(GPIO_NUM_18, 1);
			ESP_LOGI(TAG, "\n Turn on GPIO_NUM_18 \n");
		} else{
			gpio_set_level(GPIO_NUM_18, 0);
			ESP_LOGI(TAG, "\n Turn off GPIO_NUM_18 \n");
		}

		if(handle_nvs("key18", req, 1) == ESP_OK){
			pin_state = req;
			push_listener(NULL);
//			 xTaskCreate(&push_listener, "push_listener", 8192, (void*)18, 4, &TaskHandle_push_i);
		}
	}
	vTaskDelete(TaskHandle_ctrl_18);
}

static void repair_ip(void *pvParameters){
    vTaskDelay(3000 / portTICK_PERIOD_MS);
	while(1){
        xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT, false, true, portMAX_DELAY);
		char *ip_address = "";
		tcpip_adapter_ip_info_t ip;
		memset(&ip, 0, sizeof(tcpip_adapter_ip_info_t));
		if (tcpip_adapter_get_ip_info(ESP_IF_WIFI_STA, &ip) == 0) {
			ip_address = inet_ntoa(ip.ip);
		}
		if(strcmp(ip_address, (char *)uc_ip) != 0 && strcmp(ip_address, "0.0.0.0") != 0){
			ESP_LOGW(TAG, "should to update ip address");
			ESP_LOGW(TAG, "ip old %s - new %s", uc_ip, ip_address);
			snprintf(uc_ip, sizeof(uc_ip), "%s", ip_address);
			xTaskCreate(&push_device, "push_device", 8192, NULL, 3, &TaskHandle_push_d);
		}
		if(ws_check_client() == 1){ /* ws connected -> remove get task */
			handshake_ws++;
		}
    	if(handshake_ws > 9){
        	ESP_LOGW(TAG, "handshake ws have threshold. disconnect...");
//        	handshake_ws = 0;
//        	ws_set_client(); /* remove ws connection */
    	}
    	ESP_LOGI(TAG, "ip %s will restart with ws: %d", ip_address,  handshake_ws);
		vTaskDelay(1000 / portTICK_PERIOD_MS);
	}
}

void info_listener(char *buf){
	if(ws_check_client() < 1){
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
			ESP_LOGI(TAG, "type is: %d", root->type);
			if(root->type == 2){ // not found in FireBase
	//			push_device();
				if(!pushing){
	//        		xTaskCreate(&push_device, "push_device", 8192, NULL, 3, &TaskHandle_push_d);
					xTaskCreatePinnedToCore(&push_device, "push_device", 8192, NULL, 5, &TaskHandle_push_d, 1);
				}
	//	        vTaskDelay(9000 / portTICK_PERIOD_MS);
	//	        vTaskDelete(TaskHandle_get);
			} else{
				char *test = cJSON_Print(root);
				ESP_LOGI(TAG, "\ncJSON_Print----------->\n");
				printf("%s\n\n", test);
				cJSON *pin18_request = cJSON_GetObjectItem(root, "req");
				if(pin18_request != NULL){
					xTaskCreate(&control_18, "control_18", 8192, (void*)pin18_request->valueint, 4, &TaskHandle_ctrl_18);
				}
			}
		}
		cJSON_Delete(root);
	}
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
        		cJSON *response = cJSON_CreateObject();
        		cJSON *cmd = cJSON_GetObjectItem(socketQ, "cmd");
        		if(cmd != NULL){
					ESP_LOGI(TAG, "\n cmd --> %d \n", cmd->valueint);
        			switch (cmd->valueint){ // 0 => ack, 1 -> info, 2 set ssid, 3 control pin
        				case 0:{
        					handshake_ws = 0;
							cJSON_AddNumberToObject(response, "ack", 1);
        					break;
        				}
        				case 1:{ // get info
							ESP_LOGI(TAG, "\n cmd 1 --> %d \n", cmd->valueint);
							int val18 = handle_nvs("key18", 0, 0);
		        			cJSON_AddNumberToObject(response, "p18", val18);
		        			uint8_t addr[6];
							esp_efuse_mac_get_default(addr);
							char mac[18];
							snprintf(mac, sizeof(mac), "%02x-%02x-%02x-%02x-%02x-%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
							char *ip_address = "";
							tcpip_adapter_ip_info_t ip;
							memset(&ip, 0, sizeof(tcpip_adapter_ip_info_t));
							if (tcpip_adapter_get_ip_info(ESP_IF_WIFI_STA, &ip) == 0) {
								ip_address = inet_ntoa(ip.ip);
							}
							cJSON_AddStringToObject(response, "ws", (const char *)uc_ssid);
							cJSON_AddStringToObject(response, "wp", (const char *)uc_pw);
							cJSON_AddStringToObject(response, "wi", ip_address);
							cJSON_AddNumberToObject(response, "status", 1);
							break;
						}
						case 2:{ // set ssid
							ESP_LOGI(TAG, "\n cmd 2 --> %d \n", cmd->valueint);
							cJSON *ssid = cJSON_GetObjectItem(socketQ, "ssid");
							cJSON *pw = cJSON_GetObjectItem(socketQ, "pw");
							if(ssid != NULL && pw != NULL){
								handle_snvs("ssid", ssid->valuestring, 1);
								handle_snvs("pw", pw->valuestring, 1);
								cJSON_AddNumberToObject(response, "status", 1);
								if(handle_nvs("w_mode", 0, 1) == ESP_OK){
									char *res = cJSON_Print(response);
									WS_write_data(res, strlen(res));
									ESP_LOGI(TAG, "\n system will restart after %d seconds \n", 3);
								    vTaskDelay(1000 / portTICK_PERIOD_MS);
									esp_restart();
									vTaskDelete(NULL);
								} else{
									ESP_LOGI(TAG, "\n write w_mode error \n");
								}
							}
							break;
						}
						case 3:{ // control pin
							ESP_LOGI(TAG, "\n cmd 3 --> %d \n", cmd->valueint);
							cJSON *gpio_num = cJSON_GetObjectItem(socketQ, "ps");
							cJSON *gpio_req = cJSON_GetObjectItem(socketQ, "req");
							if(gpio_num != NULL && gpio_req != NULL){
								switch (gpio_num->valueint){
								case 18:
									xTaskCreate(&control_18, "control_18", 8192, (void*)gpio_req->valueint, 1, &TaskHandle_ctrl_18);
									cJSON_AddNumberToObject(response, "status", 1);
				        			break;
								default:
									break;
								}
							}
							break;
						}
						default:{
							cJSON_AddNumberToObject(response, "status", 0);
							break;
						}
					}
        		}
				char *res = cJSON_Print(response);
				ESP_LOGI(TAG, "\n %s \n", res);
				ESP_LOGI(TAG, "\n len frame: %d \n", strlen(res));
				esp_err_t err = WS_write_data(res, strlen(res));
				ESP_LOGI(TAG, "\n res %d \n", err);
//				free(response);
        	} else{
            	//loop back frame
            	WS_write_data(__RX_frame.payload, __RX_frame.payload_length);
        	}

        	//free memory
			if (__RX_frame.payload != NULL)
				free(__RX_frame.payload);

        }
    }
}

void app_main(){
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
	gpio_set_direction(GPIO_NUM_18, GPIO_MODE_OUTPUT);

	int val18 = handle_nvs("key18", 0, 0);
	ESP_LOGI(TAG, "\n key18 status: %d \n", val18);
	if(val18 >= 0){
		gpio_set_level(GPIO_NUM_18, val18);
	}
	gpio_set_direction(GPIO_NUM_14, GPIO_MODE_INPUT);
	gpio_set_intr_type(GPIO_NUM_14, GPIO_INTR_POSEDGE);
	gpio_evt_queue = xQueueCreate(10, sizeof(uint32_t));
	xTaskCreate(gpio_task_example, "gpio_task_example", 2048, NULL, 10, NULL);
	gpio_install_isr_service(ESP_INTR_FLAG_DEFAULT);
	gpio_isr_handler_add(GPIO_NUM_14, gpio_isr_handler, (void*) GPIO_NUM_14);

	handle_snvs("ssid", (char *)uc_ssid, 0);
	handle_snvs("pw", (char *)uc_pw, 0);
	handle_snvs("wi", (char *)uc_ip, 0);

	ESP_LOGI(TAG, "\n uc_ssid: %s \n", uc_ssid);
	ESP_LOGI(TAG, "\n uc_pw: %s \n", uc_pw);
	ESP_LOGI(TAG, "\n uc_ip: %s \n", uc_ip);

    uint8_t addr[6];
	esp_efuse_mac_get_default(addr);
	snprintf(uc_mac, sizeof(uc_mac), "%02x%02x%02x%02x%02x%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

	// neu ket noi duoc wifi truoc do thi bat mode sta
	if(handle_nvs("w_mode", 0, 0) < 1 && strlen((const char *)uc_ssid) > 0){
	    initialise_wifi();
//	    xTaskCreate(&https_get_task, "https_get_task", 8192, NULL, 3, &TaskHandle_get);
	    xTaskCreatePinnedToCore(&https_get_task, "https_get_task", 8192, NULL, 2, &TaskHandle_get, 1);
//	    xTaskCreate(&repair_ip, "repair_ip", 8192, NULL, 6, &TaskHandle_repair); //NULL
//	    xTaskCreatePinnedToCore(&repair_ip, "repair_ip", 8192, NULL, 3, &TaskHandle_repair, 1);
	} else{ // neu truoc do ket noi ap that bai 10 lan thi chuyen mode
		initialise_ap();
	}
//    create WebSocker receive task
    xTaskCreate(&task_process_WebSocket, "ws_process_rx", 2048, NULL, 5, NULL);
//    xTaskCreatePinnedToCore(&task_process_WebSocket, "ws_process_rx", 8192, NULL, 1, &TaskHandle_ws, 1);

//    Create Websocket Server Task
    xTaskCreate(&ws_server, "ws_server", 2048, NULL, 5, NULL);

//    printf("check socket connected: %d\n", ws_check_client());
//	ESP_LOGI(TAG, "\n ws_frame_f: %d \n", connected_f);

}
