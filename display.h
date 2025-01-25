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
            exit(1);                                                                                                                    \
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
        wattron(G_display.wins[1], COLOR_PAIR((2)));                                                                                    \
        waddstr(G_display.wins[1], "Author: Nothing");                                                                                  \
        wattroff(G_display.wins[1], COLOR_PAIR((2)));                                                                                   \
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


/** Address bar width */
#define LENGTHOFADDRESS         40
/** Width of the protocol column */
#define LENGTHOFPROTOCOL        9
/** Width of the data length column */
#define LENGTHOFDATALENGTH      7

/** Source address bar title */
#define WINTITLESOURCE          "Source"
/** The title of the destination address bar */
#define WINTITLEDESTINATION     "Destination"
/** Title of the agreement column */
#define WINTITLEPROTOCOL        "Protocol"
/** Data length column header */
#define WINTITLEDATALENGTH      "Length"
/** Title of the information bar */
#define WINTITLEINFORMATION     "Information"


/**
 * @brief Format the title bar title
 * @param win: The window that is designated to format the input title
 * @param starty: The starting position of the title bar relative to the window's Y coordinate
 * @param startx: The starting position of the title bar relative to the window's X coordinate
 * @param width: Width of the title bar
 * @param string: Contents of the title bar
 * @param color: Color attribute of the title bar content
 */
int display_format_set_window_title(WINDOW *win, int starty, int startx, int width, char *string, chtype color);


/**
 * @brief Brief information display box
 */
#define display_draw_brief_information_box()                                                                                            \
    do {                                                                                                                                \
        wattron(G_display.wins[3], COLOR_PAIR(4));                                                                                      \
		box(G_display.wins[3], 0, 0);                                                                                                   \
		wattroff(G_display.wins[3], COLOR_PAIR(4));                                                                                     \
        int line0 = 0, line1 = 1, line2 = 2;                                                                                            \
        int starty = 1, startx = 1;                                                                                                     \
        display_format_set_window_title(G_display.wins[3], starty, startx, LENGTHOFADDRESS, WINTITLESOURCE, COLOR_PAIR(4));             \
        wattron(G_display.wins[3], COLOR_PAIR(4));                                                                                      \
        mvwaddch(G_display.wins[3], line2, 0, ACS_LTEE);                                                                                \
        /** (LENGTHOFADDRESS - 1) change (LENGTHOFADDRESS) because of mark */                                                           \
        mvwhline(G_display.wins[3], line2, startx, ACS_HLINE, (LENGTHOFADDRESS));                                                       \
        startx += 1;    /** In order for the mark to be displayed */                                                                    \
        mvwaddch(G_display.wins[3], line1, (startx + (LENGTHOFADDRESS - 1)), ACS_VLINE);                                                \
        mvwaddch(G_display.wins[3], line0, (startx + (LENGTHOFADDRESS - 1)), ACS_TTEE);                                                 \
        mvwaddch(G_display.wins[3], line2, (startx + (LENGTHOFADDRESS - 1)), ACS_BTEE);                                                 \
        wattroff(G_display.wins[3], COLOR_PAIR(4));                                                                                     \
                                                                                                                                        \
        startx += LENGTHOFADDRESS;                                                                                                      \
        display_format_set_window_title(G_display.wins[3], starty, startx, LENGTHOFADDRESS, WINTITLEDESTINATION, COLOR_PAIR(4));        \
        wattron(G_display.wins[3], COLOR_PAIR(4));                                                                                      \
        mvwhline(G_display.wins[3], line2, startx, ACS_HLINE, (LENGTHOFADDRESS - 1));                                                   \
        mvwaddch(G_display.wins[3], line2, (startx + (LENGTHOFADDRESS - 1)), ACS_BTEE);                                                 \
        mvwaddch(G_display.wins[3], line1, (startx + (LENGTHOFADDRESS - 1)), ACS_VLINE);                                                \
        mvwaddch(G_display.wins[3], line0, (startx + (LENGTHOFADDRESS - 1)), ACS_TTEE);                                                 \
        wattroff(G_display.wins[3], COLOR_PAIR(4));                                                                                     \
                                                                                                                                        \
        startx += LENGTHOFADDRESS;                                                                                                      \
        display_format_set_window_title(G_display.wins[3], starty, startx, LENGTHOFPROTOCOL, WINTITLEPROTOCOL, COLOR_PAIR(4));          \
        wattron(G_display.wins[3], COLOR_PAIR(4));                                                                                      \
        mvwhline(G_display.wins[3], line2, startx, ACS_HLINE, (LENGTHOFPROTOCOL - 1));                                                  \
        mvwaddch(G_display.wins[3], line2, (startx + (LENGTHOFPROTOCOL - 1)), ACS_BTEE);                                                \
        mvwaddch(G_display.wins[3], line1, (startx + (LENGTHOFPROTOCOL - 1)), ACS_VLINE);                                               \
        mvwaddch(G_display.wins[3], line0, (startx + (LENGTHOFPROTOCOL - 1)), ACS_TTEE);                                                \
        wattroff(G_display.wins[3], COLOR_PAIR(4));                                                                                     \
                                                                                                                                        \
        startx += LENGTHOFPROTOCOL;                                                                                                     \
        display_format_set_window_title(G_display.wins[3], starty, startx, LENGTHOFDATALENGTH, WINTITLEDATALENGTH, COLOR_PAIR(4));      \
        wattron(G_display.wins[3], COLOR_PAIR(4));                                                                                      \
        mvwhline(G_display.wins[3], line2, startx, ACS_HLINE, (LENGTHOFDATALENGTH - 1));                                                \
        mvwaddch(G_display.wins[3], line2, (startx + (LENGTHOFDATALENGTH - 1)), ACS_BTEE);                                              \
        mvwaddch(G_display.wins[3], line1, (startx + (LENGTHOFDATALENGTH - 1)), ACS_VLINE);                                             \
        mvwaddch(G_display.wins[3], line0, (startx + (LENGTHOFDATALENGTH - 1)), ACS_TTEE);                                              \
        wattroff(G_display.wins[3], COLOR_PAIR(4));                                                                                     \
                                                                                                                                        \
        startx += LENGTHOFDATALENGTH;                                                                                                   \
        int width = COLS - startx;                                                                                                      \
        display_format_set_window_title(G_display.wins[3], starty, startx, width, WINTITLEINFORMATION, COLOR_PAIR(4));                  \
        wattron(G_display.wins[3], COLOR_PAIR(4));                                                                                      \
        mvwhline(G_display.wins[3], line2, startx, ACS_HLINE, (width - 1));                                                             \
        mvwaddch(G_display.wins[3], line2, (COLS - 1), ACS_RTEE);                                                                       \
        mvwaddch(G_display.wins[3], line1, (COLS - 1), ACS_VLINE);                                                                      \
        mvwaddch(G_display.wins[3], line0, (COLS - 1), ACS_URCORNER);                                                                   \
        wattroff(G_display.wins[3], COLOR_PAIR(4));                                                                                     \
                                                                                                                                        \
        refresh();                                                                                                                      \
        wrefresh(G_display.wins[3]);                                                                                                    \
    } while (0);                                                                                                                        \


/**
 * @brief Detailed information display box
 */
#define display_draw_more_information_box()                                                                                             \
    do {                                                                                                                                \
        wattron(G_display.wins[4], COLOR_PAIR(5));                                                                                      \
		box(G_display.wins[4], 0, 0);                                                                                                   \
		wattroff(G_display.wins[4], COLOR_PAIR(5));                                                                                     \
		refresh();                                                                                                                      \
		wrefresh(G_display.wins[4]);                                                                                                    \
    } while (0);                                                                                                                        \


/**
 * @brief Original hexadecimal information display box
 */
#define display_draw_raw_information_box()                                                                                              \
    do {                                                                                                                                \
        wattron(G_display.wins[5], COLOR_PAIR(6));                                                                                      \
		box(G_display.wins[5], 0, 0);                                                                                                   \
		wattroff(G_display.wins[5], COLOR_PAIR(6));                                                                                     \
		refresh();                                                                                                                      \
		wrefresh(G_display.wins[5]);                                                                                                    \
    } while (0);


/**
 * @brief Hide All Windows
 */
#define display_hide_wins_all()                                                                                                         \
    do {                                                                                                                                \
        int i = 0;                                                                                                                      \
        for (i = 0; i < (display_PW_number - 1); i++) {                                                                                 \
            hide_panel(G_display.panels[i]);                                                                                            \
        }                                                                                                                               \
        update_panels();                                                                                                                \
        doupdate();                                                                                                                     \
    } while (0);                                                                                                                        \


/**
 * @brief Hide 0 1 2 Windows
 */
#define display_hide_wins_0_1_2()                                                                                                       \
    do {                                                                                                                                \
        int i = 0;                                                                                                                      \
        for (i = 0; i < 3; i++) {                                                                                                       \
            hide_panel(G_display.panels[i]);                                                                                            \
        }                                                                                                                               \
        update_panels();                                                                                                                \
        doupdate();                                                                                                                     \
    } while (0);                                                                                                                        \


/**
 * @brief Hide 3 4 5 Windows
 */
#define display_hide_wins_3_4_5()                                                                                                       \
    do {                                                                                                                                \
        int i = 3;                                                                                                                      \
        for (i = 3; i < 6; i++) {                                                                                                       \
            hide_panel(G_display.panels[i]);                                                                                            \
        }                                                                                                                               \
        update_panels();                                                                                                                \
        doupdate();                                                                                                                     \
    } while (0);                                                                                                                        \


/**
 * @brief Show 0 1 2 Windows
 */
#define display_show_wins_0_1_2()                                                                                                       \
    do {                                                                                                                                \
        int i = 0;                                                                                                                      \
        for (i = 0; i < 3; i++) {                                                                                                       \
            show_panel(G_display.panels[i]);                                                                                            \
        }                                                                                                                               \
        update_panels();                                                                                                                \
        doupdate();                                                                                                                     \
    } while (0);                                                                                                                        \


/**
 * @brief Show 3 4 5 Windows
 */
#define display_show_wins_3_4_5()                                                                                                       \
    do {                                                                                                                                \
        int i = 3;                                                                                                                      \
        for (i = 3; i < 6; i++) {                                                                                                       \
            show_panel(G_display.panels[i]);                                                                                            \
        }                                                                                                                               \
        update_panels();                                                                                                                \
        doupdate();                                                                                                                     \
    } while (0);                                                                                                                        \


/**
 * @brief Set the properties of the 3 4 5 window
 */
#define display_set_wins_3_4_5_property()                                                                                               \
    do {                                                                                                                                \
        keypad(G_display.wins[3], TRUE);                                                                                                \
        keypad(G_display.wins[4], TRUE);                                                                                                \
        keypad(G_display.wins[5], TRUE);                                                                                                \
    } while (0);                                                                                                                        \


/**
 * @brief Set the necho and cbreak attributes for the window
 */
#define display_set_wins_noecho_and_cbreak()                                                                                            \
    do {                                                                                                                                \
        cbreak();                                                                                                                       \
	    noecho();                                                                                                                       \
    } while (0);                                                                                                                        \


/**
 * @brief Set the echo and nocbreak attributes for the window
 */
#define display_set_wins_echo_and_nocbreak()                                                                                            \
    do {                                                                                                                                \
        nocbreak();                                                                                                                     \
	    echo();                                                                                                                         \
    } while (0);                                                                                                                        \


/**
 * @brief Disable Cursor
 */
#define display_disable_cursor()                                                                                                        \
    do {                                                                                                                                \
        curs_set(0);                                                                                                                    \
    } while (0);                                                                                                                        \


/**
 * @brief Enable Cursor
 */
#define display_enable_cursor()                                                                                                         \
    do {                                                                                                                                \
        curs_set(1);                                                                                                                    \
    } while (0);                                                                                                                        \


/**
 * @brief Release members in global variables
 */
#define display_release_G_display_member()                                                                                              \
    do {                                                                                                                                \
        int i = 0;                                                                                                                      \
        for (i = 0; i < (display_PW_number - 1); i++) {                                                                                 \
            del_panel(G_display.panels[i]);                                                                                             \
            update_panels();                                                                                                            \
            delwin(G_display.wins[i]);                                                                                                  \
        }                                                                                                                               \
    } while (0);                                                                                                                        \


/**
 * @brief Called ncurses endwin end Environment
 */
#define display_endwin()                                                                                                                \
    do {                                                                                                                                \
        endwin();                                                                                                                       \
    } while (0);                                                                                                                        \


/**
 * @brief Exit TUI Showcase
 */
#define display_exit_TUI_showcase()                                                                                                     \
    do {                                                                                                                                \
        display_release_G_display_member();                                                                                             \
        display_endwin();                                                                                                               \
    } while (0);                                                                                                                        \


/**
 * @brief Handle TUI first page
 */
#define display_handle_TUI_first_page()                                                                                                 \
    do {                                                                                                                                \
        display_show_wins_0_1_2();                                                                                                      \
        while (1) {                                                                                                                     \
            wmove(G_display.wins[2], 1, 1);                                                                                             \
            wattrset(G_display.wins[2], A_NORMAL);                                                                                      \
            wclrtoeol(G_display.wins[2]);                                                                                               \
            wattrset(G_display.wins[2], A_BOLD);                                                                                        \
            wattron(G_display.wins[2], COLOR_PAIR((3)));                                                                                \
            waddstr(G_display.wins[2], "Command: ");                                                                                    \
            wattroff(G_display.wins[2], COLOR_PAIR((3)));                                                                               \
            wattron(G_display.wins[2], COLOR_PAIR((2)));                                                                                \
            box(G_display.wins[2], 0, 0);                                                                                               \
            wattroff(G_display.wins[2], COLOR_PAIR((2)));                                                                               \
            refresh();                                                                                                                  \
            wrefresh(G_display.wins[2]);                                                                                                \
            int code = OK;                                                                                                              \
            char buffer[256] = {0};                                                                                                     \
            code = wgetnstr(G_display.wins[2], buffer, 256);                                                                            \
            if (code == ERR) {                                                                                                          \
                display_exit_TUI_showcase();                                                                                            \
                trace_log("Called wgetnstr error");                                                                                     \
                exit(1);                                                                                                                \
            }                                                                                                                           \
            attroff(A_BOLD);                                                                                                            \
            refresh();                                                                                                                  \
            wrefresh(G_display.wins[2]);                                                                                                \
            mvwprintw(stdscr, 0, 0, "%s\n", buffer);                                                                                    \
            refresh();                                                                                                                  \
            wrefresh(stdscr);                                                                                                           \
            if (!strncmp("Quit", buffer, 4)) {                                                                                          \
                display_exit_TUI_showcase();                                                                                            \
                trace_log("Called wgetnstr error");                                                                                     \
                exit(1);                                                                                                                \
            }                                                                                                                           \
            else {                                                                                                                      \
                break;                                                                                                                  \
            }                                                                                                                           \
        }                                                                                                                               \
        display_hide_wins_0_1_2();                                                                                                      \
    } while (0);                                                                                                                        \


/**
 * @brief Select 3 windows
 */
#define display_select_3_windows()                                                                                                      \
    do {                                                                                                                                \
        wattron(G_display.wins[3], A_REVERSE);                                                                                          \
        display_draw_brief_information_box();                                                                                           \
        wattroff(G_display.wins[3], A_REVERSE);                                                                                         \
        display_draw_more_information_box();                                                                                            \
        display_draw_raw_information_box();                                                                                             \
} while (0);                                                                                                                            \


/**
 * @brief Select 4 windows
 */
#define display_select_4_windows()                                                                                                      \
    do {                                                                                                                                \
        display_draw_brief_information_box();                                                                                           \
        wattron(G_display.wins[4], A_REVERSE);                                                                                          \
        display_draw_more_information_box();                                                                                            \
        wattroff(G_display.wins[4], A_REVERSE);                                                                                         \
        display_draw_raw_information_box();                                                                                             \
} while (0);                                                                                                                            \


/**
 * @brief Select 5 windows  
 */
#define display_select_5_windows()                                                                                                      \
    do {                                                                                                                                \
        display_draw_brief_information_box();                                                                                           \
        display_draw_more_information_box();                                                                                            \
        wattron(G_display.wins[5], A_REVERSE);                                                                                          \
        display_draw_raw_information_box();                                                                                             \
        wattroff(G_display.wins[5], A_REVERSE);                                                                                         \
} while (0);                                                                                                                            \


/**
 * @brief Handle TUI second page
 */
#define display_handle_TUI_second_page()                                                                                                \
    do {                                                                                                                                \
        display_show_wins_3_4_5();                                                                                                      \
        display_set_wins_noecho_and_cbreak();                                                                                           \
        display_disable_cursor();                                                                                                       \
        int ch = 0;                                                                                                                     \
        unsigned char count = 0;                                                                                                        \
        while((ch = getch()) != 80) {	                                                                                                \
            switch(ch) {	                                                                                                            \
                case 9:                                                                                                                 \
                    switch (((count % 3) + 3)) {                                                                                        \
                        case 3:                                                                                                         \
                            display_select_3_windows();                                                                                 \
                            break;                                                                                                      \
                        case 4:                                                                                                         \
                            display_select_4_windows();                                                                                 \
                            break;                                                                                                      \
                        case 5:                                                                                                         \
                            display_select_5_windows();                                                                                 \
                            break;                                                                                                      \
                        default:                                                                                                        \
                            break;                                                                                                      \
                    }                                                                                                                   \
                    break;                                                                                                              \
                default:                                                                                                                \
                    break;                                                                                                              \
            }                                                                                                                           \
            count ++;                                                                                                                   \
        }                                                                                                                               \
        display_hide_wins_3_4_5();                                                                                                      \
        display_set_wins_echo_and_nocbreak();                                                                                           \
        display_enable_cursor();                                                                                                        \
    } while (0);                                                                                                                        \


/**
 * @brief TUI processing entry
 */
#define display_TUI_processing_entry()                                                                                                  \
    do {                                                                                                                                \
        while (1) {                                                                                                                     \
            display_handle_TUI_first_page();                                                                                            \
            display_handle_TUI_second_page();                                                                                           \
        }                                                                                                                               \
    } while (0);                                                                                                                        \


/**
 * @brief Startup TUI Showcase
 */
#define display_startup_TUI_showcase()                                                                                                  \
    do {                                                                                                                                \
                                                                                                                                        \
        display_initialize_scr();                                                                                                       \
                                                                                                                                        \
        display_initialize_color();                                                                                                     \
                                                                                                                                        \
        display_initialize_color_pair();                                                                                                \
                                                                                                                                        \
        display_apply_first_tui_wins_resources();                                                                                       \
                                                                                                                                        \
        display_apply_first_tui_panels_resources();                                                                                     \
                                                                                                                                        \
        display_apply_second_tui_wins_resources();                                                                                      \
                                                                                                                                        \
        display_apply_second_tui_panels_resources();                                                                                    \
                                                                                                                                        \
        display_check_G_display();                                                                                                      \
                                                                                                                                        \
        display_set_wins_3_4_5_property();                                                                                              \
                                                                                                                                        \
        display_draw_netdump_ASCII_world();                                                                                             \
                                                                                                                                        \
        display_draw_author_information();                                                                                              \
                                                                                                                                        \
        display_draw_cmd_input_box();                                                                                                   \
                                                                                                                                        \
        display_draw_brief_information_box();                                                                                           \
                                                                                                                                        \
        display_draw_more_information_box();                                                                                            \
                                                                                                                                        \
        display_draw_raw_information_box();                                                                                             \
                                                                                                                                        \
        display_hide_wins_all();                                                                                                        \
                                                                                                                                        \
        display_TUI_processing_entry();                                                                                                 \
    } while (0);                                                                                                                        \


#endif  // __DISPLAY_H__