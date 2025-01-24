/**
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 */

#ifndef __DISPLAY_H__
#define __DISPLAY_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "panel.h"
#include "ncurses.h"

#include "trace.h"


/**
 * @brief The number of windows and panels used globally
 */
#define display_PW_number               7


/**
 * @brief Stores resources required by the TUI 
 * @param wins: Window resources required by the TUI 
 * @param panels: Panel resources required by the TUI 
 */
typedef struct {

    WINDOW * wins[display_PW_number];
    PANEL * panels[display_PW_number];

} display_t;


/** For external use */
extern display_t G_display;


/**
 * @brief Called ncurses initscr initialize environment
 */
#define display_initialize_scr()                                                                                                        \
    do {                                                                                                                                \
        initscr();                                                                                                                      \
    } while (0);                                                                                                                        \


/**
 * @brief Check whether the color attribute can be used and enable the color attribute
 */
#define display_initialize_color()                                                                                                      \
    do {                                                                                                                                \
        if (!has_colors()) {                                                                                                            \
            trace_log("Don't support color attribute");                                                                                 \
            assert(1);                                                                                                                  \
        }                                                                                                                               \
        start_color();                                                                                                                  \
    } while (0);                                                                                                                        \


/**
 * @brief Set color pair
 */
#define display_initialize_color_pair()                                                                                                 \
    do {                                                                                                                                \
        init_pair(1, COLOR_WHITE, COLOR_BLACK);                                                                                         \
        init_pair(2, COLOR_WHITE, COLOR_BLACK);                                                                                         \
        init_pair(3, COLOR_WHITE, COLOR_BLACK);                                                                                         \
        init_pair(4, COLOR_RED, COLOR_BLACK);                                                                                           \
        init_pair(5, COLOR_BLUE, COLOR_BLACK);                                                                                          \
        init_pair(6, COLOR_CYAN, COLOR_BLACK);                                                                                          \
    } while (0);                                                                                                                        \


/**
 * @brief Apply for window resources for the first page
 */
#define display_apply_first_tui_wins_resources()                                                                                        \
    do {                                                                                                                                \
        /* 1. Netdump ASCII art word */                                                                                                 \
        int nlines = 8;                                                                                                                 \
        int ncols = 58;                                                                                                                 \
        int nybegin = LINES / 4;                                                                                                        \
        int nxbegin = (COLS - 56) / 2;                                                                                                  \
        G_display.wins[0] = newwin(nlines, ncols, nybegin, nxbegin);                                                                    \
                                                                                                                                        \
        /* 2. Author info */                                                                                                            \
        int infonlines = 3;                                                                                                             \
        int infoncols = strlen("Author: Nothing") + 2;                                                                                  \
        int infonybegin = nybegin + 18;                                                                                                 \
        int infonxbegin = (COLS - strlen("Author: Nothing")) / 2;                                                                       \
        G_display.wins[1] = newwin(infonlines, infoncols, infonybegin, infonxbegin);                                                    \
                                                                                                                                        \
        /* 3. command input box */                                                                                                      \
        int cmdnlines = 3;                                                                                                              \
        int cmdncols = COLS - 25;                                                                                                       \
        int cmdnybegin = nybegin + 11;                                                                                                  \
        int cmdnxbegin = (COLS - cmdncols) / 2;                                                                                         \
        G_display.wins[2] = newwin(cmdnlines, cmdncols, cmdnybegin, cmdnxbegin);                                                        \
    } while (0);                                                                                                                        \


/**
 * @brief Apply for panel resources for the first page
 */
#define display_apply_first_tui_panels_resources()                                                                                      \
    do {                                                                                                                                \
        G_display.panels[0] = new_panel(G_display.wins[0]);                                                                             \
        G_display.panels[1] = new_panel(G_display.wins[1]);                                                                             \
        G_display.panels[2] = new_panel(G_display.wins[2]);                                                                             \
    } while (0);                                                                                                                        \


/**
 * @brief Apply for window resources for the second page
 */
#define display_apply_second_tui_wins_resources()                                                                                       \
    do {                                                                                                                                \
        int twlines = (LINES / 2) + 1;                                                                                                  \
        int twcols = COLS;                                                                                                              \
        int twybegin = 0;                                                                                                               \
        int twxbegin = 0;                                                                                                               \
                                                                                                                                        \
        int lwlines = LINES - twlines;                                                                                                  \
        int lwcols = COLS / 2;                                                                                                          \
        int lwybegin = twlines;                                                                                                         \
        int lwxbegin = 0;                                                                                                               \
                                                                                                                                        \
        int rwlines = LINES - twlines;                                                                                                  \
        int rwcols = COLS - lwcols;                                                                                                     \
        int rwybegin = twlines;                                                                                                         \
        int rwxbegin = lwcols;                                                                                                          \
                                                                                                                                        \
        /* 3. Brief information display box*/                                                                                           \
        G_display.wins[3] = newwin(twlines, twcols, twybegin, twxbegin);                                                                \
                                                                                                                                        \
        /* 4. Detailed information display box */                                                                                       \
        G_display.wins[4] = newwin(lwlines, lwcols, lwybegin, lwxbegin);                                                                \
                                                                                                                                        \
        /* 5. Original hexadecimal information display box */                                                                           \
        G_display.wins[5] = newwin(rwlines, rwcols, rwybegin, rwxbegin);                                                                \
    } while (0);                                                                                                                        \


/**
 * @brief Apply for panel resources for the second page
 */
#define display_apply_second_tui_panels_resources()                                                                                     \
    do {                                                                                                                                \
        G_display.panels[3] = new_panel(G_display.wins[3]);                                                                             \
        G_display.panels[4] = new_panel(G_display.wins[4]);                                                                             \
        G_display.panels[5] = new_panel(G_display.wins[5]);                                                                             \
    } while (0);                                                                                                                        \


/**
 * @brief Check if a member of a global variable is NULL
 */
#define display_check_G_display()                                                                                                       \
    do {                                                                                                                                \
        int i = 0;                                                                                                                      \
        for (i = 0; i < (display_PW_number - 1); i++) {                                                                                 \
            if (!(G_display.wins[i])) {                                                                                                 \
                trace_log("G_display.wins[%d]", i);                                                                                     \
                assert((G_display.wins[i]) != NULL);                                                                                    \
            }                                                                                                                           \
            if (!(G_display.panels[i])) {                                                                                               \
                trace_log("G_display.panels[%d]", i);                                                                                   \
                assert((G_display.panels[i]) != NULL);                                                                                  \
            }                                                                                                                           \
        }                                                                                                                               \
    } while (0);                                                                                                                        \


/**
 * @brief draw netdump ASCII world
 */
#define display_draw_netdump_ASCII_world()                                                                                              \
    do {                                                                                                                                \
        wattron(G_display.wins[0], COLOR_PAIR((1)));                                                                                    \
        mvwprintw(G_display.wins[0], 1, 1," _   _          _     ____                              ");                                  \
        mvwprintw(G_display.wins[0], 2, 1, "| \\ | |   ___  | |_  |  _ \\   _   _   _ __ ___    _ __  ");                               \
        mvwprintw(G_display.wins[0], 3, 1, "|  \\| |  / _ \\ | __| | | | | | | | | | '_ ` _ \\  | '_ \\ ");                             \
        mvwprintw(G_display.wins[0], 4, 1, "| |\\  | |  __/ | |_  | |_| | | |_| | | | | | | | | |_) |");                                \
        mvwprintw(G_display.wins[0], 5, 1, "|_| \\_|  \\___|  \\__| |____/   \\__,_| |_| |_| |_| | .__/ ");                             \
        mvwprintw(G_display.wins[0], 6, 1, "                                                 |_|    ");                                 \
        wattroff(G_display.wins[0], COLOR_PAIR((1)));                                                                                   \
        refresh();                                                                                                                      \
        wrefresh(G_display.wins[0]);                                                                                                    \
    } while (0);                                                                                                                        \


/**
 * @brief draw Information of author
 */
#define display_draw_author_information()                                                                                               \
    do {                                                                                                                                \
        wmove(G_display.wins[1], 1, 1);                                                                                                 \
        wattrset(G_display.wins[1], A_NORMAL);                                                                                          \
        wclrtoeol(G_display.wins[1]);                                                                                                   \
        wattrset(G_display.wins[1], A_BOLD);                                                                                            \
        wattron(G_display.wins[1], COLOR_PAIR((4)));                                                                                    \
        waddstr(G_display.wins[1], "Author: Nothing");                                                                                  \
        wattroff(G_display.wins[1], COLOR_PAIR((4)));                                                                                   \
        refresh();                                                                                                                      \
        wrefresh(G_display.wins[1]);                                                                                                    \
    } while (0);                                                                                                                        \


/**
 * @brief draw Command input box
 */
#define display_draw_cmd_input_box()                                                                                                    \
    do {                                                                                                                                \
        wmove(G_display.wins[2], 1, 1);                                                                                                 \
        wattrset(G_display.wins[2], A_NORMAL);                                                                                          \
        wclrtoeol(G_display.wins[2]);                                                                                                   \
        wattrset(G_display.wins[2], A_BOLD);                                                                                            \
        wattron(G_display.wins[2], COLOR_PAIR((3)));                                                                                    \
        waddstr(G_display.wins[2], "Command: ");                                                                                        \
        wattroff(G_display.wins[2], COLOR_PAIR((3)));                                                                                   \
        wattron(G_display.wins[2], COLOR_PAIR((2)));                                                                                    \
        box(G_display.wins[2], 0, 0);                                                                                                   \
        wattroff(G_display.wins[2], COLOR_PAIR((2)));                                                                                   \
        refresh();                                                                                                                      \
        wrefresh(G_display.wins[2]);                                                                                                    \
    } while (0);                                                                                                                        \

/**
 * @brief Release members in global variables
 */
#define display_release_G_display_member()                                                                                              \
    do {                                                                                                                                \
        int i = 0;                                                                                                                      \
        for (i = 0; i < (display_PW_number - 1); i++) {                                                                                 \
            delwin(G_display.wins[i]);                                                                                                  \
            del_panel(G_display.panels[i]);                                                                                             \
        }                                                                                                                               \
    } while (0);                                                                                                                        \


/**
 * @brief Called ncurses endwin end Environment
 */
#define display_endwin()                                                                                                                \
    do {                                                                                                                                \
        endwin();                                                                                                                       \
    } while (0);                                                                                                                        \

#endif  // __DISPLAY_H__