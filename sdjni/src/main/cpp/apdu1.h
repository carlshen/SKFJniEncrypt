//
// Created by carl on 20-2-16.
//

#ifndef SDK_APDU_H
#define SDK_APDU_H

#include <stdint.h>
//#include "sdk.h"

static const char * APDU_DEV_ASC = "tmssim";
static const uint8_t APDU_DEV_HEX[] = { 0x74, 0x6D, 0x73, 0x73, 0x69, 0x6D };
static const uint8_t APDU_9000[2] = { 0x90, 0x00 };
static const uint8_t APDU_CMD_A4[4] = { 0x00, 0xA4, 0x04, 0x00 };
static const uint8_t APDU_CMD_A5[4] = { 0x00, 0xA5, 0x00, 0x00 };
static const uint8_t APDU_CMD_D6[4] = { 0x00, 0xA5, 0x00, 0x00 };
static const uint8_t APDU_CMD_B0[4] = { 0x00, 0xB0, 0x00, 0x00 };
static const uint8_t APDU_CMD_84[4] = { 0x00, 0x84, 0x00, 0x00 };
static const uint8_t APDU_CMD_C8[4] = { 0x80, 0xC8, 0x00, 0x00 };
static const uint8_t APDU_CMD_C1[4] = { 0x80, 0xC1, 0x00, 0x00 };
static const uint8_t APDU_CMD_D1[4] = { 0x80, 0xD1, 0x00, 0x00 };
static const uint8_t APDU_CMD_CC[4] = { 0x80, 0xCC, 0x00, 0x00 };
static const uint8_t APDU_CMD_CE[4] = { 0x80, 0xCE, 0x00, 0x00 };
static const uint8_t APDU_CMD_E1[4] = { 0x80, 0xE1, 0x00, 0x00 };
static const uint8_t APDU_CMD_F1[4] = { 0x80, 0xF1, 0x00, 0x00 };
static const uint8_t APDU_CMD_F4[4] = { 0x80, 0xF4, 0x00, 0x00 };
static const uint8_t APDU_CMD_F8[4] = { 0x80, 0xF8, 0x00, 0x00 };
static const uint8_t APDU_CMD_FA[4] = { 0x80, 0xFA, 0x00, 0x00 };
static const uint8_t APDU_CMD_FC[4] = { 0x80, 0xFC, 0x00, 0x00 };
static const uint8_t APDU_SIGN_ID1[2] = { 0x00, 0x01 };
static const uint8_t APDU_SIGN_ID2[2] = { 0x00, 0x02 };
static const uint8_t APDU_PRIV_ID1[2] = { 0xA1, 0x01 };
static const uint8_t APDU_PRIV_ID2[2] = { 0xA1, 0x02 };
static const uint8_t APDU_PUBL_ID1[2] = { 0xA0, 0x01 };
static const uint8_t APDU_PUBL_ID2[2] = { 0xA0, 0x02 };
static const uint8_t APDU_TEMP_ID1[2] = { 0xB0, 0x01 };
static const uint8_t APDU_TEMP_ID2[2] = { 0xB1, 0x01 };

#endif //SDK_APDU_H
