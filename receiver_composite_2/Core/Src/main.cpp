/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2023 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "usb_device.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "usbd_cdc_if.h"
#include "crypto.h"
#include "stdio.h"
#include <string>
#include "rs.hpp"
using namespace std;

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
//#define USB_TX_BUF_SIZE 1024 // Can Transmit max of 256 chars over USB
#define USB_TX_BUF_SIZE 129 // Can Transmit max of 256 chars over USB
#define UART_RX_BUF_SIZE 1  // Receive each UART byte one at a time

#define AES_BLOCK_LENGTH 8
#define PLAINTEXT_LENGTH  16
#define ECC_LENGTH 12
#define RS_MESSAGE_LENGTH 129
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
ADC_HandleTypeDef hadc1;
ADC_HandleTypeDef hadc2;

CRC_HandleTypeDef hcrc;

IWDG_HandleTypeDef hiwdg;

TIM_HandleTypeDef htim2;

UART_HandleTypeDef huart1;

/* USER CODE BEGIN PV */
char usbTxBuf[USB_TX_BUF_SIZE];
uint8_t UART1_rxBuffer[UART_RX_BUF_SIZE] = {0};

uint32_t adc_reading;
int agc_lvl;

//vars for decoding
uint8_t uart5_byte_1;
uint8_t uart5_byte_2;
uint8_t byte_out;
uint8_t byte_out_nibble_1;
uint8_t byte_out_nibble_2;
uint8_t uart_byte_dummy;

uint8_t current_byte;
uint8_t prev_byte;

uint8_t AES_Key[CRL_AES128_KEY] =
{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

bool timing_correct_flag;
bool start_decryption_flag = false;

uint8_t count = 1;
int error_code;

int rs_encoded_count = 0;
uint8_t manchester_encoded_buff[2*(RS_MESSAGE_LENGTH + ECC_LENGTH)];
uint8_t manchester_encoded_buff_cpy[2*(RS_MESSAGE_LENGTH + ECC_LENGTH)];
uint8_t rs_encoded_buff[RS_MESSAGE_LENGTH + ECC_LENGTH];

// Reed Solomon decoding variables
char reed_solomon_repaired[RS_MESSAGE_LENGTH];

// AES Decoding variables
uint8_t output_split_ciphertext[8][PLAINTEXT_LENGTH];  // Input plaintext split into 16 byte chunks
uint8_t output_split_plaintext[8][PLAINTEXT_LENGTH];  // Input plaintext split into 16 byte chunks

char output_message[RS_MESSAGE_LENGTH];
uint32_t output_message_length = 0;







RS::ReedSolomon<RS_MESSAGE_LENGTH, ECC_LENGTH> rs; 		        // Reed solomon encoder data structure

int indexing_dummy = 0;

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_IWDG_Init(void);
static void MX_ADC1_Init(void);
static void MX_ADC2_Init(void);
static void MX_CRC_Init(void);
static void MX_USART1_UART_Init(void);
static void MX_TIM2_Init(void);
/* USER CODE BEGIN PFP */
void DecodeManchester(void);
string DecryptData(void);
void CombineAES2DArray(uint8_t input_ciphertext[][PLAINTEXT_LENGTH], char output_str[]);
int32_t AESDecrypt2DArray(uint8_t input_ciphertext[][PLAINTEXT_LENGTH], uint8_t output_plaintext[][PLAINTEXT_LENGTH]);




//void SplitStringForAESDecoding(string input_str, uint8_t output_ptr[][PLAINTEXT_LENGTH]);
void SplitStringForAESDecoding(char input_str[], uint8_t output_ptr[][PLAINTEXT_LENGTH]);






int32_t STM32_AES_ECB_Decrypt(uint8_t* InputMessage,
                              uint32_t InputMessageLength,
                              uint8_t *AES256_Key,
                              uint8_t  *OutputMessage,
                              uint32_t *OutputMessageLength);

void SetAGCLevel(int lvl);
void UpdateAGC(uint32_t adc_val_in);
void ResetGlobalVars(void);
/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{
  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */
  __CRC_CLK_ENABLE();
  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_USB_DEVICE_Init();
  MX_IWDG_Init();
  MX_ADC1_Init();
  MX_ADC2_Init();
  MX_CRC_Init();
  MX_USART1_UART_Init();
  MX_TIM2_Init();
  /* USER CODE BEGIN 2 */
  HAL_UART_Receive_IT(&huart1, UART1_rxBuffer, UART_RX_BUF_SIZE);
  HAL_TIM_Base_Start_IT(&htim2);

  //ResetGlobalVars();

  HAL_Delay(50);

  sprintf(usbTxBuf, "IWDG Reset");
  CDC_Transmit_FS((uint8_t *) usbTxBuf, strlen(usbTxBuf));

  if(HAL_IWDG_Refresh(&hiwdg) != HAL_OK)
  {
		sprintf(usbTxBuf, "IWDG Error");
		CDC_Transmit_FS((uint8_t *) usbTxBuf, strlen(usbTxBuf));

		Error_Handler();
  }
  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  start_decryption_flag = false;
  while (1)
  {
	  if(start_decryption_flag == true)
	  {
		  DecodeManchester();
		  DecryptData();

		  if((output_message[0] == 'L') && (output_message[1] == 'i') && (output_message[2] == 'F'))
		  {
			  //if(rs_encoded_count < 125)
			  if(error_code == 0)
			  {
			  sprintf(usbTxBuf, "%s", output_message);
			  CDC_Transmit_FS((uint8_t *) usbTxBuf, strlen(usbTxBuf));
			  }
		  }

		  //sprintf(usbTxBuf, "\n\rError Code: %d\n\r", error_code);
		  //CDC_Transmit_FS((uint8_t *) usbTxBuf, strlen(usbTxBuf));

		  for(int i = 0; i < RS_MESSAGE_LENGTH; i++) // reset output buffer array
		  {
			  output_message[i] = 0x00;
		  }

/*
		  for(int i = 0; i < 2*(RS_MESSAGE_LENGTH + ECC_LENGTH); i++)
		  {
			  manchester_encoded_buff[i] = 0x00;
		  }
*/

		  start_decryption_flag = false;

		  while(start_decryption_flag == false)
		  {
			  indexing_dummy++;
		  }
	  }
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
  }
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};
  RCC_PeriphCLKInitTypeDef PeriphClkInit = {0};

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_LSI|RCC_OSCILLATORTYPE_HSE;
  RCC_OscInitStruct.HSEState = RCC_HSE_ON;
  RCC_OscInitStruct.HSEPredivValue = RCC_HSE_PREDIV_DIV1;
  RCC_OscInitStruct.HSIState = RCC_HSI_ON;
  RCC_OscInitStruct.LSIState = RCC_LSI_ON;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
  RCC_OscInitStruct.PLL.PLLMUL = RCC_PLL_MUL9;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV2;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_2) != HAL_OK)
  {
    Error_Handler();
  }
  PeriphClkInit.PeriphClockSelection = RCC_PERIPHCLK_ADC|RCC_PERIPHCLK_USB;
  PeriphClkInit.AdcClockSelection = RCC_ADCPCLK2_DIV6;
  PeriphClkInit.UsbClockSelection = RCC_USBCLKSOURCE_PLL_DIV1_5;
  if (HAL_RCCEx_PeriphCLKConfig(&PeriphClkInit) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief ADC1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_ADC1_Init(void)
{

  /* USER CODE BEGIN ADC1_Init 0 */

  /* USER CODE END ADC1_Init 0 */

  ADC_ChannelConfTypeDef sConfig = {0};

  /* USER CODE BEGIN ADC1_Init 1 */

  /* USER CODE END ADC1_Init 1 */

  /** Common config
  */
  hadc1.Instance = ADC1;
  hadc1.Init.ScanConvMode = ADC_SCAN_DISABLE;
  hadc1.Init.ContinuousConvMode = DISABLE;
  hadc1.Init.DiscontinuousConvMode = DISABLE;
  hadc1.Init.ExternalTrigConv = ADC_SOFTWARE_START;
  hadc1.Init.DataAlign = ADC_DATAALIGN_RIGHT;
  hadc1.Init.NbrOfConversion = 1;
  if (HAL_ADC_Init(&hadc1) != HAL_OK)
  {
    Error_Handler();
  }

  /** Configure Regular Channel
  */
  sConfig.Channel = ADC_CHANNEL_8;
  sConfig.Rank = ADC_REGULAR_RANK_1;
  sConfig.SamplingTime = ADC_SAMPLETIME_1CYCLE_5;
  if (HAL_ADC_ConfigChannel(&hadc1, &sConfig) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN ADC1_Init 2 */

  /* USER CODE END ADC1_Init 2 */

}

/**
  * @brief ADC2 Initialization Function
  * @param None
  * @retval None
  */
static void MX_ADC2_Init(void)
{

  /* USER CODE BEGIN ADC2_Init 0 */

  /* USER CODE END ADC2_Init 0 */

  ADC_ChannelConfTypeDef sConfig = {0};

  /* USER CODE BEGIN ADC2_Init 1 */

  /* USER CODE END ADC2_Init 1 */

  /** Common config
  */
  hadc2.Instance = ADC2;
  hadc2.Init.ScanConvMode = ADC_SCAN_DISABLE;
  hadc2.Init.ContinuousConvMode = DISABLE;
  hadc2.Init.DiscontinuousConvMode = DISABLE;
  hadc2.Init.ExternalTrigConv = ADC_SOFTWARE_START;
  hadc2.Init.DataAlign = ADC_DATAALIGN_RIGHT;
  hadc2.Init.NbrOfConversion = 1;
  if (HAL_ADC_Init(&hadc2) != HAL_OK)
  {
    Error_Handler();
  }

  /** Configure Regular Channel
  */
  sConfig.Channel = ADC_CHANNEL_9;
  sConfig.Rank = ADC_REGULAR_RANK_1;
  sConfig.SamplingTime = ADC_SAMPLETIME_1CYCLE_5;
  if (HAL_ADC_ConfigChannel(&hadc2, &sConfig) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN ADC2_Init 2 */

  /* USER CODE END ADC2_Init 2 */

}

/**
  * @brief CRC Initialization Function
  * @param None
  * @retval None
  */
static void MX_CRC_Init(void)
{

  /* USER CODE BEGIN CRC_Init 0 */

  /* USER CODE END CRC_Init 0 */

  /* USER CODE BEGIN CRC_Init 1 */

  /* USER CODE END CRC_Init 1 */
  hcrc.Instance = CRC;
  if (HAL_CRC_Init(&hcrc) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN CRC_Init 2 */

  /* USER CODE END CRC_Init 2 */

}

/**
  * @brief IWDG Initialization Function
  * @param None
  * @retval None
  */
static void MX_IWDG_Init(void)
{

  /* USER CODE BEGIN IWDG_Init 0 */

  /* USER CODE END IWDG_Init 0 */

  /* USER CODE BEGIN IWDG_Init 1 */

  /* USER CODE END IWDG_Init 1 */
  hiwdg.Instance = IWDG;
  hiwdg.Init.Prescaler = IWDG_PRESCALER_32;
  hiwdg.Init.Reload = 1299;
  if (HAL_IWDG_Init(&hiwdg) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN IWDG_Init 2 */

  /* USER CODE END IWDG_Init 2 */

}

/**
  * @brief TIM2 Initialization Function
  * @param None
  * @retval None
  */
static void MX_TIM2_Init(void)
{

  /* USER CODE BEGIN TIM2_Init 0 */

  /* USER CODE END TIM2_Init 0 */

  TIM_ClockConfigTypeDef sClockSourceConfig = {0};
  TIM_MasterConfigTypeDef sMasterConfig = {0};

  /* USER CODE BEGIN TIM2_Init 1 */

  /* USER CODE END TIM2_Init 1 */
  htim2.Instance = TIM2;
  htim2.Init.Prescaler = 7199;
  htim2.Init.CounterMode = TIM_COUNTERMODE_UP;
  htim2.Init.Period = 1000;
  htim2.Init.ClockDivision = TIM_CLOCKDIVISION_DIV1;
  htim2.Init.AutoReloadPreload = TIM_AUTORELOAD_PRELOAD_DISABLE;
  if (HAL_TIM_Base_Init(&htim2) != HAL_OK)
  {
    Error_Handler();
  }
  sClockSourceConfig.ClockSource = TIM_CLOCKSOURCE_INTERNAL;
  if (HAL_TIM_ConfigClockSource(&htim2, &sClockSourceConfig) != HAL_OK)
  {
    Error_Handler();
  }
  sMasterConfig.MasterOutputTrigger = TIM_TRGO_RESET;
  sMasterConfig.MasterSlaveMode = TIM_MASTERSLAVEMODE_DISABLE;
  if (HAL_TIMEx_MasterConfigSynchronization(&htim2, &sMasterConfig) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN TIM2_Init 2 */

  /* USER CODE END TIM2_Init 2 */

}

/**
  * @brief USART1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART1_UART_Init(void)
{

  /* USER CODE BEGIN USART1_Init 0 */

  /* USER CODE END USART1_Init 0 */

  /* USER CODE BEGIN USART1_Init 1 */

  /* USER CODE END USART1_Init 1 */
  huart1.Instance = USART1;
  huart1.Init.BaudRate = 115200;
  huart1.Init.WordLength = UART_WORDLENGTH_8B;
  huart1.Init.StopBits = UART_STOPBITS_1;
  huart1.Init.Parity = UART_PARITY_NONE;
  huart1.Init.Mode = UART_MODE_TX_RX;
  huart1.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart1.Init.OverSampling = UART_OVERSAMPLING_16;
  if (HAL_UART_Init(&huart1) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART1_Init 2 */

  /* USER CODE END USART1_Init 2 */

}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOD_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(GPIOB, GPIO_PIN_12|GPIO_PIN_13|GPIO_PIN_14, GPIO_PIN_RESET);

  /*Configure GPIO pins : PB12 PB13 PB14 */
  GPIO_InitStruct.Pin = GPIO_PIN_12|GPIO_PIN_13|GPIO_PIN_14;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(GPIOB, &GPIO_InitStruct);

}

/* USER CODE BEGIN 4 */
void ResetGlobalVars(void)
{
	for(int i = 0; i < USB_TX_BUF_SIZE; i++)
	{
		usbTxBuf[i] = 0x00;
	}

	for(int i = 0; i < UART_RX_BUF_SIZE; i++)
	{
		UART1_rxBuffer[i] = 0x00;
	}

	count = 1;

	uart5_byte_1 = 0x00;
	uart5_byte_2 = 0x00;
	byte_out = 0x00;
	byte_out_nibble_1 = 0x00;
	byte_out_nibble_2 = 0x00;
	uart_byte_dummy = 0x00;

	current_byte = 0x77;
	prev_byte = 0x77;

	timing_correct_flag = false;

	rs_encoded_count = 0;

	for(int i = 0; i < 2*(RS_MESSAGE_LENGTH + ECC_LENGTH); i++)
	{
		manchester_encoded_buff[i] = 0x00;
		manchester_encoded_buff_cpy[i] = 0x00;
	}

	for(int i = 0; i < RS_MESSAGE_LENGTH + ECC_LENGTH; i++)
	{

		rs_encoded_buff[i] = 0x00;
	}

	start_decryption_flag = false;

	output_message_length = 0;

	error_code = 0;

	for(int i = 0; i < RS_MESSAGE_LENGTH; i++)
	{
		reed_solomon_repaired[i] = 0x00;
	}

	for(int i = 0; i < AES_BLOCK_LENGTH; i++)
	{
		for(int j = 0; j < PLAINTEXT_LENGTH; j++)
		{
			output_split_ciphertext[i][j] = 0x00;
			output_split_plaintext[i][j] = 0x00;
		}
	}

	for(int i = 0; i < RS_MESSAGE_LENGTH; i++)
	{
		output_message[i] = 0x00;
	}
	adc_reading = 0;
	agc_lvl = 0;
}

void UpdateAGC(uint32_t adc_val_in)
{
	//ORIGINAL NUMBERS THAT WORK: 900 -> 1800

	//if((adc_val_in > 1800) && (agc_lvl > 0)) //DC value is too high -> decrease gain
	if((adc_val_in > 2200) && (agc_lvl > 0)) //DC value is too high -> decrease gain
	{
		agc_lvl--;
		SetAGCLevel(agc_lvl);
	}
	//else if((adc_val_in < 1050) && (agc_lvl < 4)) //DC value is too low -> increase gain
	//else if((adc_val_in < 1250) && (agc_lvl < 4)) //DC value is too low -> increase gain
	else if((adc_val_in < 1250) && (agc_lvl < 3)) //DC value is too low -> increase gain
	{
		agc_lvl++;
		SetAGCLevel(agc_lvl);
	}

	//sprintf(usbTxBuf, "\n\rL%d\n\r", agc_lvl);
	//CDC_Transmit_FS((uint8_t *) usbTxBuf, strlen(usbTxBuf));
}

void SetAGCLevel(int lvl)
{
	if(lvl == 1) //Y0
	{
		HAL_GPIO_WritePin(GPIOB, GPIO_PIN_12|GPIO_PIN_13|GPIO_PIN_14, GPIO_PIN_RESET);
	}
	else if(lvl == 2) //Y1
	{
		HAL_GPIO_WritePin(GPIOB, GPIO_PIN_12|GPIO_PIN_13, GPIO_PIN_RESET);
		HAL_GPIO_WritePin(GPIOB, GPIO_PIN_14, GPIO_PIN_SET);
	}
	else if(lvl == 3) //Y2
	{
		HAL_GPIO_WritePin(GPIOB, GPIO_PIN_12|GPIO_PIN_14, GPIO_PIN_RESET);
		HAL_GPIO_WritePin(GPIOB, GPIO_PIN_13, GPIO_PIN_SET);
	}
	else if(lvl == 4) //Y4
	{
		HAL_GPIO_WritePin(GPIOB, GPIO_PIN_13|GPIO_PIN_14, GPIO_PIN_RESET);
		HAL_GPIO_WritePin(GPIOB, GPIO_PIN_12, GPIO_PIN_SET);
	}
	else if(lvl == 5) //Y6
	{
		HAL_GPIO_WritePin(GPIOB, GPIO_PIN_14, GPIO_PIN_RESET);
		HAL_GPIO_WritePin(GPIOB, GPIO_PIN_12|GPIO_PIN_13, GPIO_PIN_SET);
	}
	else //Y3 (Lowest gain level)
	{
		HAL_GPIO_WritePin(GPIOB, GPIO_PIN_13|GPIO_PIN_14, GPIO_PIN_SET);
		HAL_GPIO_WritePin(GPIOB, GPIO_PIN_12, GPIO_PIN_RESET);
	}
}

void DecodeManchester(void)
{
	memcpy(manchester_encoded_buff_cpy, manchester_encoded_buff, sizeof(manchester_encoded_buff_cpy));

	/*
	for(int i = 0; i < 2*(RS_MESSAGE_LENGTH + ECC_LENGTH); i++)
	{
		manchester_encoded_buff[i] = 0x00;
	}
	*/

	byte_out = 0x00;
	byte_out_nibble_1 = 0x00;
	byte_out_nibble_2 = 0x00;


	//decoding manchester
	for(int i = 0; i < RS_MESSAGE_LENGTH + ECC_LENGTH; i++)
	{
		byte_out = 0x00;
		byte_out_nibble_1 = 0x00;
		byte_out_nibble_2 = 0x00;

		uart5_byte_1 = manchester_encoded_buff_cpy[2*i];
		uart5_byte_2 = manchester_encoded_buff_cpy[2*i + 1];


		if((uart5_byte_1 & 0xC0) == 0x40) // 8th bit is rising edge = one
		{
			byte_out_nibble_1 = byte_out_nibble_1 | 0x08;     // Turn 8th bit to 1
		}
		if((uart5_byte_1 & 0x30) == 0x10) // 7th bit is rising edge = one
		{
			byte_out_nibble_1 = byte_out_nibble_1 | 0x04;     // Turn 7th bit to 1
		}
		if((uart5_byte_1 & 0x0C) == 0x04) // 6th bit is rising edge = one
		{
			byte_out_nibble_1 = byte_out_nibble_1 | 0x02;     // Turn 6th bit to 1
		}
		if((uart5_byte_1 & 0x03) == 0x01) // 5th bit is rising edge = one
		{
			byte_out_nibble_1 = byte_out_nibble_1 | 0x01;     // Turn 5th bit to 1
		}

		if((uart5_byte_2 & 0xC0) == 0x40) // 4th bit is rising edge = one
		{
			byte_out_nibble_2 = byte_out_nibble_2 | 0x08;     // Turn 4th bit to 1
		}
		if((uart5_byte_2 & 0x30) == 0x10) // 3rd bit is rising edge = one
		{
			byte_out_nibble_2 = byte_out_nibble_2 | 0x04;     // Turn 3rd bit to 1
		}
		if((uart5_byte_2 & 0x0C) == 0x04) // 2nd bit is rising edge = one
		{
			byte_out_nibble_2 = byte_out_nibble_2 | 0x02;     // Turn 2nd bit to 1
		}
		if((uart5_byte_2 & 0x03) == 0x01) // 1st bit is rising edge = one
		{
			byte_out_nibble_2 = byte_out_nibble_2 | 0x01;     // Turn 1st bit to 1
		}

		rs_encoded_buff[i] = (byte_out_nibble_1<<4) | byte_out_nibble_2;
	}
}

string DecryptData(void)
{
	// NOTE: This returns 0 if it worked, 1 if there was problem (too many corrupted bits
	error_code = rs.Decode(rs_encoded_buff, reed_solomon_repaired);       // Corrects bits errors - output is 129 bytes
	SplitStringForAESDecoding(reed_solomon_repaired, output_split_ciphertext); // Split message into 16 byte chunks and removes the termininating '\0' char
	//SplitStringForAESDecoding((string)reed_solomon_repaired, output_split_ciphertext); // Split message into 16 byte chunks and removes the termininating '\0' char
	AESDecrypt2DArray(output_split_ciphertext, output_split_plaintext);        // Decrypt each AES block
	CombineAES2DArray(output_split_plaintext, output_message);                 // Put all decrypted AES blocks into single char array

	return string(output_message);
}

//void SplitStringForAESDecoding(string input_str, uint8_t output_ptr[][PLAINTEXT_LENGTH])
void SplitStringForAESDecoding(char input_str[], uint8_t output_ptr[][PLAINTEXT_LENGTH])
{
	//int n = sizeof(input_str);
	//int n = 128;

	//if((n <= AES_BLOCK_LENGTH * PLAINTEXT_LENGTH) && (start_decrytion_flag == true))
	//{
		for(int i = 0; i < AES_BLOCK_LENGTH; i++)
		{
			for(int j = 0; j < PLAINTEXT_LENGTH; j++)
			{
				//if(((PLAINTEXT_LENGTH*i) + j) < n)
				//{
					output_ptr[i][j] = input_str[(PLAINTEXT_LENGTH*i) + j];
					indexing_dummy = (PLAINTEXT_LENGTH*i) + j;
				//}
			}
		}
	//}
}

int32_t STM32_AES_ECB_Decrypt(uint8_t* InputMessage,
                              uint32_t InputMessageLength,
                              uint8_t  *AES256_Key,
                              uint8_t  *OutputMessage,
                              uint32_t *OutputMessageLength)
{
  AESECBctx_stt AESctx;

  uint32_t error_status = AES_SUCCESS;

  int32_t outputLength = 0;

  /* Set flag field to default value */
  AESctx.mFlags = E_SK_DEFAULT;

  /* Set key size to 32 (corresponding to AES-256) */
  //AESctx.mKeySize = 32;
  AESctx.mKeySize = 16;

  /* Initialize the operation, by passing the key.
   * Third parameter is NULL because ECB doesn't use any IV */
  error_status = AES_ECB_Decrypt_Init(&AESctx, AES256_Key, NULL );

  /* check for initialization errors */
  if (error_status == AES_SUCCESS)
  {
    /* Decrypt Data */
    error_status = AES_ECB_Decrypt_Append(&AESctx,
                                          InputMessage,
                                          InputMessageLength,
                                          OutputMessage,
                                          &outputLength);

    if (error_status == AES_SUCCESS)
    {
      /* Write the number of data written*/
      *OutputMessageLength = outputLength;
      /* Do the Finalization */
      error_status = AES_ECB_Decrypt_Finish(&AESctx, OutputMessage + *OutputMessageLength, &outputLength);
      /* Add data written to the information to be returned */
      *OutputMessageLength += outputLength;
    }
  }

  return error_status;
}

int32_t AESDecrypt2DArray(uint8_t input_ciphertext[][PLAINTEXT_LENGTH], uint8_t output_plaintext[][PLAINTEXT_LENGTH])
{
	int32_t encrypt_status_temp;
	for(int i = 0; i < AES_BLOCK_LENGTH; i++)
	{
		encrypt_status_temp = STM32_AES_ECB_Decrypt(input_ciphertext[i], PLAINTEXT_LENGTH, AES_Key, output_plaintext[i], &output_message_length);
		if(encrypt_status_temp != AES_SUCCESS)
		{
			return encrypt_status_temp;
		}
	}
	return AES_SUCCESS;
}

void CombineAES2DArray(uint8_t input_ciphertext[][PLAINTEXT_LENGTH], char output_str[])
{
	for(int i = 0; i < AES_BLOCK_LENGTH; i++)
	{
		for(int j = 0; j < PLAINTEXT_LENGTH; j++)
		{
			output_str[(PLAINTEXT_LENGTH*i) + j] = (char)input_ciphertext[i][j];
		}
	}

	output_str[RS_MESSAGE_LENGTH-1] = '\0'; // make the last (129th) byte null terminiating char
}

void HAL_TIM_PeriodElapsedCallback(TIM_HandleTypeDef *htim)
{
	if(HAL_IWDG_Refresh(&hiwdg) != HAL_OK)
	{
		sprintf(usbTxBuf, "IWDG Error");
		CDC_Transmit_FS((uint8_t *) usbTxBuf, strlen(usbTxBuf));

		Error_Handler();
	}

	HAL_ADC_Start(&hadc1);
	HAL_ADC_PollForConversion(&hadc1, 1);
	adc_reading = HAL_ADC_GetValue(&hadc1);

	UpdateAGC(adc_reading);

	//sprintf(usbTxBuf, "\n\r%d", (int)adc_reading);
	//CDC_Transmit_FS((uint8_t *) usbTxBuf, strlen(usbTxBuf));
}

void HAL_UART_RxCpltCallback(UART_HandleTypeDef *huart)
{
	//HAL_UART_Receive_IT(&huart1, UART1_rxBuffer, 2);
	HAL_UART_Receive_IT(&huart1, UART1_rxBuffer, UART_RX_BUF_SIZE);

	prev_byte = current_byte;
	current_byte = UART1_rxBuffer[0];

	if(current_byte == 0x00)
	{
		if(prev_byte == 0x00) // correct timing
		{
			rs_encoded_count = 0;
			return;
		}
		else // incorrect timing
		{
			return;
		}
	}
	//if(rs_encoded_count < 2*(ECC_LENGTH + RS_MESSAGE_LENGTH))
	if(rs_encoded_count < 2*(ECC_LENGTH + RS_MESSAGE_LENGTH))
	{
		manchester_encoded_buff[rs_encoded_count] = current_byte;
		rs_encoded_count = rs_encoded_count + 1;
	}
	//if(rs_encoded_count == 2*(ECC_LENGTH + RS_MESSAGE_LENGTH))
	if(rs_encoded_count >= 2*(ECC_LENGTH + RS_MESSAGE_LENGTH))
	{
		start_decryption_flag = true;
		rs_encoded_count = 0;
	}
	else
	{
		start_decryption_flag = false;
	}
}
/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}

#ifdef  USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
