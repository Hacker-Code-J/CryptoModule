/* File : include/ansi_code.h */

/**
 * @file ansi_code.h
 * @brief ANSI escape codes for terminal text formatting.
 * @details This header file defines ANSI escape codes for various text styles and colors.
 */

#ifndef ANSI_CODES_H
#define ANSI_CODES_H

/* Reset */
#define ANSI_RESET            "\x1b[0m"

/* Text Styles */
#define ANSI_BOLD             "\x1b[1m"
#define ANSI_DIM              "\x1b[2m"
#define ANSI_ITALIC           "\x1b[3m"
#define ANSI_UNDERLINE        "\x1b[4m"
#define ANSI_BLINK            "\x1b[5m"
#define ANSI_REVERSE          "\x1b[7m"
#define ANSI_HIDDEN           "\x1b[8m"
#define ANSI_STRIKETHROUGH    "\x1b[9m"

/* Foreground Colors */
#define ANSI_FG_BLACK         "\x1b[30m"
#define ANSI_FG_RED           "\x1b[31m"
#define ANSI_FG_GREEN         "\x1b[32m"
#define ANSI_FG_YELLOW        "\x1b[33m"
#define ANSI_FG_BLUE          "\x1b[34m"
#define ANSI_FG_MAGENTA       "\x1b[35m"
#define ANSI_FG_CYAN          "\x1b[36m"
#define ANSI_FG_WHITE         "\x1b[37m"

/* Bright Foreground Colors */
#define ANSI_FG_BBLACK        "\x1b[90m"
#define ANSI_FG_BRED          "\x1b[91m"
#define ANSI_FG_BGREEN        "\x1b[92m"
#define ANSI_FG_BYELLOW       "\x1b[93m"
#define ANSI_FG_BBLUE         "\x1b[94m"
#define ANSI_FG_BMAGENTA      "\x1b[95m"
#define ANSI_FG_BCYAN         "\x1b[96m"
#define ANSI_FG_BWHITE        "\x1b[97m"

/* Background Colors */
#define ANSI_BG_BLACK         "\x1b[40m"
#define ANSI_BG_RED           "\x1b[41m"
#define ANSI_BG_GREEN         "\x1b[42m"
#define ANSI_BG_YELLOW        "\x1b[43m"
#define ANSI_BG_BLUE          "\x1b[44m"
#define ANSI_BG_MAGENTA       "\x1b[45m"
#define ANSI_BG_CYAN          "\x1b[46m"
#define ANSI_BG_WHITE         "\x1b[47m"
#define ANSI_BG_DEFAULT       "\x1b[49m"

/* Bright Background Colors */
#define ANSI_BG_BBLACK        "\x1b[100m"
#define ANSI_BG_BRED          "\x1b[101m"
#define ANSI_BG_BGREEN        "\x1b[102m"
#define ANSI_BG_BYELLOW       "\x1b[103m"
#define ANSI_BG_BBLUE         "\x1b[104m"
#define ANSI_BG_BMAGENTA      "\x1b[105m"
#define ANSI_BG_BCYAN         "\x1b[106m"
#define ANSI_BG_BWHITE        "\x1b[107m"

#endif /* ANSI_CODES_H */
