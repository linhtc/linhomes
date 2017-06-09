/* tcp_perf Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/


/*
tcp_perf example

Using this example to test tcp throughput performance.
esp<->esp or esp<->ap

step1:
    init wifi as AP/STA using config SSID/PASSWORD.

step2:
    create a tcp server/client socket using config PORT/(IP).
    if server: wating for connect.
    if client connect to server.
step3:
    send/receive data to/from each other.
    if the tcp connect established. esp will send or receive data.
    you can see the info in serial output.
*/

#include <errno.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_log.h"
#include "esp_err.h"

#include <string.h>
#include <sys/socket.h>
#include "esp_wifi.h"
#include "esp_event_loop.h"

//#include "tcp_perf.h"

#define EXAMPLE_DEFAULT_SSID "Leon A.one"
#define EXAMPLE_DEFAULT_PWD "11330232"
#define EXAMPLE_PACK_BYTE_IS 97 //'a'
#define WIFI_CONNECTED_BIT BIT0
#define TAG "tcp_perf:"
static int connect_socket = 0;

EventGroupHandle_t tcp_event_group;

int get_socket_error_code(int socket)
{
    int result;
    u32_t optlen = sizeof(int);
    if(getsockopt(socket, SOL_SOCKET, SO_ERROR, &result, &optlen) == -1) {
		ESP_LOGE(TAG, "getsockopt failed");
		return -1;
    }
    return result;
}

int show_socket_error_reason(int socket)
{
    int err = get_socket_error_code(socket);
    ESP_LOGW(TAG, "socket error %d %s", err, strerror(err));
    return err;
}

void send_data(void *pvParameters)
{
    int len = 0;
    char databuff[1460];
    memset(databuff, EXAMPLE_PACK_BYTE_IS, 1460);
    vTaskDelay(100/portTICK_RATE_MS);
    ESP_LOGI(TAG, "start sending...");
    while(1) {
    	len = send(connect_socket, databuff, 1460, 0);
		if(len < 0) {
			if (LOG_LOCAL_LEVEL >= ESP_LOG_DEBUG) {
				show_socket_error_reason(connect_socket);
			}
		}
    }
}

void recv_data(void *pvParameters)
{
    int len = 0;
    char databuff[1460];
    while (1) {
		len = recv(connect_socket, databuff, 1460, 0);
		if (len > 0) {
			send_data(NULL);
		} else {
			if (LOG_LOCAL_LEVEL >= ESP_LOG_DEBUG) {
				show_socket_error_reason(connect_socket);
			}
			vTaskDelay(100 / portTICK_RATE_MS);
		}
    }
}

static void tcp_conn(void *pvParameters)
{
    ESP_LOGI(TAG, "task tcp_conn.");
    xEventGroupWaitBits(tcp_event_group, WIFI_CONNECTED_BIT,false, true, portMAX_DELAY);

	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	struct sockaddr_in serverAddress;
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);
	serverAddress.sin_port = htons(4567);
	bind(sock, (struct sockaddr *)&serverAddress, sizeof(serverAddress));
	listen(sock, 4);
	struct sockaddr_in client_addr;
	unsigned int socklen = sizeof(client_addr);
	connect_socket = accept(sock, (struct sockaddr*)&client_addr, &socklen);
	ESP_LOGI(TAG, "tcp socket established");
	TaskHandle_t tx_rx_task;
	xTaskCreate(&recv_data, "recv_data", 4096, NULL, 4, &tx_rx_task);
}

static esp_err_t event_handler(void *ctx, system_event_t *event)
{
    switch(event->event_id) {
    case SYSTEM_EVENT_STA_START:
        esp_wifi_connect();
        break;
    case SYSTEM_EVENT_STA_DISCONNECTED:
        esp_wifi_connect();
        xEventGroupClearBits(tcp_event_group, WIFI_CONNECTED_BIT);
        break;
    case SYSTEM_EVENT_STA_CONNECTED:
        break;
    case SYSTEM_EVENT_STA_GOT_IP:
    	ESP_LOGI(TAG, "got ip:%s\n",
		ip4addr_ntoa(&event->event_info.got_ip.ip_info.ip));
    	xEventGroupSetBits(tcp_event_group, WIFI_CONNECTED_BIT);
        break;
    case SYSTEM_EVENT_AP_STACONNECTED:
    	ESP_LOGI(TAG, "station:"MACSTR" join,AID=%d\n",
		MAC2STR(event->event_info.sta_connected.mac),
		event->event_info.sta_connected.aid);
    	xEventGroupSetBits(tcp_event_group, WIFI_CONNECTED_BIT);
    	break;
    case SYSTEM_EVENT_AP_STADISCONNECTED:
    	ESP_LOGI(TAG, "station:"MACSTR"leave,AID=%d\n",
		MAC2STR(event->event_info.sta_disconnected.mac),
		event->event_info.sta_disconnected.aid);
    	xEventGroupClearBits(tcp_event_group, WIFI_CONNECTED_BIT);
    	break;
    default:
        break;
    }
    return ESP_OK;
}

void wifi_init_sta()
{
    tcp_event_group = xEventGroupCreate();

    tcpip_adapter_init();
    ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL) );

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    wifi_config_t wifi_config = {
        .sta = {
            .ssid = EXAMPLE_DEFAULT_SSID,
            .password = EXAMPLE_DEFAULT_PWD
        },
    };

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config) );
    ESP_ERROR_CHECK(esp_wifi_start() );

    ESP_LOGI(TAG, "wifi_init_sta finished.");
    ESP_LOGI(TAG, "connect to ap SSID:%s password:%s \n",
	    EXAMPLE_DEFAULT_SSID,EXAMPLE_DEFAULT_PWD);
}

void app_main(void)
{
    wifi_init_sta();
    xTaskCreate(&tcp_conn, "tcp_conn", 4096, NULL, 5, NULL);
}
