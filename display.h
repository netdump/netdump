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
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <sys/ioctl.h>

#include "panel.h"
#include "ncurses.h"

#include "trace.h"
#include "msgcomm.h"


/**
 * @brief 
 *  The global flag of display tui, used to exit tui
 * @note
 * 	display_G_flag = 1; 
 * 	indicates an exception occurs and the system needs to exit
 */
extern volatile unsigned char display_G_flag;

/**
 * @brief
 * 	Whether the SIGWINCH signal is received
 * @note
 * 	The default initial value is 0
 * 	display_G_sigwinch_flag = 1;
 * 	After receiving the signal, display_G_sigwinch_flag is set to 1
 * 	display_G_sigwinch_flag = 0;
 * 	After redrawing the interface, display_G_sigwinch_flag is set to 0
 */
extern volatile unsigned char display_G_sigwinch_flag;

/**
 * @brief
 * 	Stores the old values ​​of LINES
 */
extern volatile unsigned int display_old_lines;

/**
 * @brief
 * 	Stores the old values ​​of COLS
 */
extern volatile unsigned int display_old_cols;


/**
 * @brief
 *  Desired terminal COLS
 */
#define DISPLAY_EXPECT_TERMINAL_COLS            206

/**
 * @brief
 *  Desired terminal LINES
 */
#define DISPLAY_EXPECT_TERMINAL_LINES           42


/**
 * @brief 
 *  The number of windows and panels used globally
 */
#define display_PW_number               9


/**
 * @brief
 *  Define the size and starting position of each window
 */
#define DISPLAY_WINS_0_NLINES               (8)
#define DISPLAY_WINS_0_NCOLS                (58)
#define DISPLAY_WINS_0_NYBEGIN              (LINES / 4)
#define DISPLAY_WINS_0_NXBEGIN              ((COLS - 56) / 2)

#define DISPLAY_WINS_1_NLINES               (3)
#define DISPLAY_WINS_1_NCOLS                (strlen("Author: Nothing") + 2)
#define DISPLAY_WINS_1_NYBEGIN              (DISPLAY_WINS_0_NYBEGIN + 18)
#define DISPLAY_WINS_1_NXBEGIN              ((COLS - strlen("Author: Nothing")) / 2)

#define DISPLAY_WINS_2_NLINES               (3)
#define DISPLAY_WINS_2_NCOLS                (COLS - 25)
#define DISPLAY_WINS_2_NYBEGIN              (DISPLAY_WINS_0_NYBEGIN + 11)
#define DISPLAY_WINS_2_NXBEGIN              ((COLS - DISPLAY_WINS_2_NCOLS) / 2)

#define DISPLAY_WINS_3_NLINES               ((LINES / 2) + 1)
#define DISPLAY_WINS_3_NCOLS                (COLS)
#define DISPLAY_WINS_3_NYBEGIN              (0)
#define DISPLAY_WINS_3_NXBEGIN              (0)

#define DISPLAY_WINS_4_NLINES               (LINES - DISPLAY_WINS_3_NLINES)
#define DISPLAY_WINS_4_NCOLS                (COLS / 2)
#define DISPLAY_WINS_4_NYBEGIN              (DISPLAY_WINS_3_NLINES)
#define DISPLAY_WINS_4_NXBEGIN              (0)

#define DISPLAY_WINS_5_NLINES               (LINES - DISPLAY_WINS_3_NLINES)
#define DISPLAY_WINS_5_NCOLS                (COLS - DISPLAY_WINS_4_NCOLS)
#define DISPLAY_WINS_5_NYBEGIN              (DISPLAY_WINS_3_NLINES)
#define DISPLAY_WINS_5_NXBEGIN              (DISPLAY_WINS_4_NCOLS)

#define DISPLAY_WINS_6_NLINES               (16)
#define DISPLAY_WINS_6_NCOLS                (COLS - 12)
#define DISPLAY_WINS_6_NYBEGIN              ((LINES - DISPLAY_WINS_6_NLINES) / 2)
#define DISPLAY_WINS_6_NXBEGIN              ((COLS - DISPLAY_WINS_6_NCOLS) / 2)

#define DISPLAY_WINS_7_NLINES               ((LINES - 8))
#define DISPLAY_WINS_7_NCOLS                ((COLS - 8))
#define DISPLAY_WINS_7_NYBEGIN              ((LINES - DISPLAY_WINS_7_NLINES) / 2)
#define DISPLAY_WINS_7_NXBEGIN              ((COLS - DISPLAY_WINS_7_NCOLS) / 2)

/**
 * @brief 
 *  Stores resources required by the TUI 
 * @param wins: 
 *  Window resources required by the TUI 
 * @param panels: 
 *  Panel resources required by the TUI 
 */
typedef struct {

    WINDOW * wins[display_PW_number];
    PANEL * panels[display_PW_number];

} display_t;


/** For external use */
extern display_t G_display;


/**
 * @brief 
 * 	The display process communicates with the capture process
 * @param command
 * 	Pointer to the message content
 * @return 
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int display_cmd_to_capture (const char * command);


/**
 * @brief 
 * 	Receive messages from the capture process
 * @param message
 * 	Storing Messages
 * @return 
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int display_reply_from_capture (message_t * message);


/**
 * @brief
 * 	sigwinch signal processing function
 * @param signum
 * 	Signal number
 */
void display_handle_winch_signal(int signum);


/**
 * @brief
 * 	Redraw the interface after the interface size changes
 * @param flag
 * 	Flags for the first TUI interface and the second TUI interface
 * 	flag = 1 indicates the first TUI interface
 * 	flag = 2 indicates the second TUI interface
 */
void display_handle_win_resize(int flag);

/**
 * @brief
 * 	dump size infomation
 */
void diaplay_dump_size_info(void);

/**
 * @brief
 * 	Detection terminal size
 */
void display_check_term_size(void);

/**
 * @brief 
 *  Called ncurses initscr initialize environment
 */
#define display_initialize_scr()                                                                                                        \
    do {                                                                                                                                \
        if(!(initscr())) {                                                                                                              \
            TE("Can't initscr");                                                                                                        \
            display_G_flag = 1;                                                                                                         \
        }                                                                                                                               \
        display_old_cols = COLS;                                                                                                        \
        display_old_lines = LINES;                                                                                                      \
        diaplay_dump_size_info();                                                                                                       \
                                                                                                                                        \
    } while (0);                                                                                                                        \


/**
 * @brief 
 *  Check whether the color attribute can be used and enable the color attribute
 */
#define display_initialize_color()                                                                                                      \
    do {                                                                                                                                \
        if (!has_colors()) {                                                                                                            \
            TE("Don't support color attribute");                                                                                        \
            display_G_flag = 1;                                                                                                         \
        }                                                                                                                               \
        start_color();                                                                                                                  \
    } while (0);                                                                                                                        \


/**
 * @brief 
 *  Set color pair
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
 * @brief 
 *  Apply for window resources for the first page
 */
#define display_apply_first_tui_wins_resources()                                                                                        \
    do {                                                                                                                                \
        /* 1. Netdump ASCII art word */                                                                                                 \
        int nlines = DISPLAY_WINS_0_NLINES;                                                                                             \
        int ncols = DISPLAY_WINS_0_NCOLS;                                                                                               \
        int nybegin = DISPLAY_WINS_0_NYBEGIN;                                                                                           \
        int nxbegin = DISPLAY_WINS_0_NXBEGIN;                                                                                           \
        G_display.wins[0] = newwin(nlines, ncols, nybegin, nxbegin);                                                                    \
                                                                                                                                        \
        /* 2. Author info */                                                                                                            \
        int infonlines = DISPLAY_WINS_1_NLINES;                                                                                         \
        int infoncols = DISPLAY_WINS_1_NCOLS;                                                                                           \
        int infonybegin = DISPLAY_WINS_1_NYBEGIN;                                                                                       \
        int infonxbegin = DISPLAY_WINS_1_NXBEGIN;                                                                                       \
        G_display.wins[1] = newwin(infonlines, infoncols, infonybegin, infonxbegin);                                                    \
                                                                                                                                        \
        /* 3. command input box */                                                                                                      \
        int cmdnlines = DISPLAY_WINS_2_NLINES;                                                                                          \
        int cmdncols = DISPLAY_WINS_2_NCOLS;                                                                                            \
        int cmdnybegin = DISPLAY_WINS_2_NYBEGIN;                                                                                        \
        int cmdnxbegin = DISPLAY_WINS_2_NXBEGIN;                                                                                        \
        G_display.wins[2] = newwin(cmdnlines, cmdncols, cmdnybegin, cmdnxbegin);                                                        \
                                                                                                                                        \
        /* 4. error message show */                                                                                                     \
        int errnlines = DISPLAY_WINS_6_NLINES;                                                                                          \
        int errncols = DISPLAY_WINS_6_NCOLS;                                                                                            \
        int errnybegin = DISPLAY_WINS_6_NYBEGIN;                                                                                        \
        int errnxbegin = DISPLAY_WINS_6_NXBEGIN;                                                                                        \
        G_display.wins[6] = newwin(errnlines, errncols, errnybegin, errnxbegin);                                                        \
                                                                                                                                        \
        /* 5. info message show */                                                                                                      \
        int helpnlines = DISPLAY_WINS_7_NLINES;                                                                                         \
        int helpncols = DISPLAY_WINS_7_NCOLS;                                                                                           \
        int helpnybegin = DISPLAY_WINS_7_NYBEGIN;                                                                                       \
        int helpnxbegin = DISPLAY_WINS_7_NXBEGIN;                                                                                       \
        G_display.wins[7] = newwin(helpnlines, helpncols, helpnybegin, helpnxbegin);                                                    \
    } while (0);                                                                                                                        \


/**
 * @brief 
 *  Apply for panel resources for the first page
 */
#define display_apply_first_tui_panels_resources()                                                                                      \
    do {                                                                                                                                \
        G_display.panels[0] = new_panel(G_display.wins[0]);                                                                             \
        G_display.panels[1] = new_panel(G_display.wins[1]);                                                                             \
        G_display.panels[2] = new_panel(G_display.wins[2]);                                                                             \
        G_display.panels[6] = new_panel(G_display.wins[6]);                                                                             \
        G_display.panels[7] = new_panel(G_display.wins[7]);                                                                             \
    } while (0);                                                                                                                        \


/**
 * @brief 
 *  Apply for window resources for the second page
 */
#define display_apply_second_tui_wins_resources()                                                                                       \
    do {                                                                                                                                \
        int twlines = DISPLAY_WINS_3_NLINES;                                                                                            \
        int twcols = DISPLAY_WINS_3_NCOLS;                                                                                              \
        int twybegin = DISPLAY_WINS_3_NYBEGIN;                                                                                          \
        int twxbegin = DISPLAY_WINS_3_NXBEGIN;                                                                                          \
                                                                                                                                        \
        int lwlines = DISPLAY_WINS_4_NLINES;                                                                                            \
        int lwcols = DISPLAY_WINS_4_NCOLS;                                                                                              \
        int lwybegin = DISPLAY_WINS_4_NYBEGIN;                                                                                          \
        int lwxbegin = DISPLAY_WINS_4_NXBEGIN;                                                                                          \
                                                                                                                                        \
        int rwlines = DISPLAY_WINS_5_NLINES;                                                                                            \
        int rwcols = DISPLAY_WINS_5_NCOLS;                                                                                              \
        int rwybegin = DISPLAY_WINS_5_NYBEGIN;                                                                                          \
        int rwxbegin = DISPLAY_WINS_5_NXBEGIN;                                                                                          \
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
 * @brief 
 *  Apply for panel resources for the second page
 */
#define display_apply_second_tui_panels_resources()                                                                                     \
    do {                                                                                                                                \
        G_display.panels[3] = new_panel(G_display.wins[3]);                                                                             \
        G_display.panels[4] = new_panel(G_display.wins[4]);                                                                             \
        G_display.panels[5] = new_panel(G_display.wins[5]);                                                                             \
    } while (0);                                                                                                                        \


/**
 * @brief 
 *  Check if a member of a global variable is NULL
 */
#define display_check_G_display()                                                                                                       \
    do {                                                                                                                                \
        int i = 0;                                                                                                                      \
        for (i = 0; i < (display_PW_number - 1); i++) {                                                                                 \
            if (!(G_display.wins[i])) {                                                                                                 \
                TE("G_display.wins[%d] is NULL", i);                                                                                    \
                display_G_flag = 1;                                                                                                     \
                break;                                                                                                                  \
            }                                                                                                                           \
            if (!(G_display.panels[i])) {                                                                                               \
                TE("G_display.panels[%d] is NULL", i);                                                                                  \
                display_G_flag = 1;                                                                                                     \
                break;                                                                                                                  \
            }                                                                                                                           \
        }                                                                                                                               \
    } while (0);                                                                                                                        \


/**
 * @brief 
 *  draw netdump ASCII world
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
 * @brief 
 *  draw Information of author
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
 * @brief 
 *  draw Command input box
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
 * @brief
 *  Format the title bar title
 * @param win:
 *  The window that is designated to format the input title
 * @param starty:
 *  The starting position of the title bar relative to the window's Y coordinate
 * @param startx:
 *  The starting position of the title bar relative to the window's X coordinate
 * @param width:
 *  Width of the title bar
 * @param string:
 *  Contents of the title bar
 * @param color:
 *  Color attribute of the title bar content
 */
int display_format_set_window_title(WINDOW *win, int starty, int startx, int width, char *string, chtype color);

/**
 * @brief
 * 	Display the processing logic interface of the first interface of the process
 * @param command
 * 	Commands entered via the tui interface
 * @param errwin
 * 	Error message display window
 * @param errpanel
 * 	Error message window control panel
 * @param infowin
 * 	info message display window
 * @param infopanel
 * 	info message window control panel
 * @return
 *  If successful, it returns ND_OK;
 *  if failed, it returns ND_ERR
 */
int display_first_tui_handle_logic(const char *command, WINDOW *errwin, PANEL *errpanel, WINDOW *infowin, PANEL *infopanel);

/**
 * @brief 
 *  Brief information display box
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
 * @brief 
 *  Detailed information display box
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
 * @brief 
 *  Original hexadecimal information display box
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
 * @brief 
 *  Hide All Windows
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
 * @brief 
 *  Hide 0 1 2 Windows
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
 * @brief 
 *  Hide 3 4 5 Windows
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
 * @brief 
 *  Show 0 1 2 Windows
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
 * @brief 
 *  Show 3 4 5 Windows
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
 * @brief 
 *  Set the properties of the 3 4 5 window
 */
#define display_set_wins_3_4_5_property()                                                                                               \
    do {                                                                                                                                \
        keypad(G_display.wins[3], TRUE);                                                                                                \
        keypad(G_display.wins[4], TRUE);                                                                                                \
        keypad(G_display.wins[5], TRUE);                                                                                                \
    } while (0);                                                                                                                        \


/**
 * @brief 
 *  Set the necho and cbreak attributes for the window
 */
#define display_set_wins_noecho_and_cbreak()                                                                                            \
    do {                                                                                                                                \
        cbreak();                                                                                                                       \
	    noecho();                                                                                                                       \
    } while (0);                                                                                                                        \


/**
 * @brief 
 *  Set the echo and nocbreak attributes for the window
 */
#define display_set_wins_echo_and_nocbreak()                                                                                            \
    do {                                                                                                                                \
        nocbreak();                                                                                                                     \
	    echo();                                                                                                                         \
    } while (0);                                                                                                                        \


/**
 * @brief 
 *  Disable Cursor
 */
#define display_disable_cursor()                                                                                                        \
    do {                                                                                                                                \
        curs_set(0);                                                                                                                    \
    } while (0);                                                                                                                        \


/**
 * @brief 
 *  Enable Cursor
 */
#define display_enable_cursor()                                                                                                         \
    do {                                                                                                                                \
        curs_set(1);                                                                                                                    \
    } while (0);                                                                                                                        \


/**
 * @brief 
 *  Release members in global variables
 */
#define display_release_G_display_member()                                                                                              \
    do {                                                                                                                                \
        int i = 0;                                                                                                                      \
        for (i = 0; i < (display_PW_number - 1); i++) {                                                                                 \
            if (G_display.panels[i]) {                                                                                                  \
                del_panel(G_display.panels[i]);                                                                                         \
                update_panels();                                                                                                        \
                G_display.panels[i] = NULL;                                                                                             \
            }                                                                                                                           \
            if (G_display.wins[i]) {                                                                                                    \
                delwin(G_display.wins[i]);                                                                                              \
                G_display.wins[i] = NULL;                                                                                               \
            }                                                                                                                           \
        }                                                                                                                               \
    } while (0);                                                                                                                        \


/**
 * @brief 
 *  Called ncurses endwin end Environment
 */
#define display_endwin()                                                                                                                \
    do {                                                                                                                                \
        endwin();                                                                                                                       \
    } while (0);                                                                                                                        \


/**
 * @brief 
 *  Exit TUI Showcase
 */
#define display_exit_TUI_showcase()                                                                                                     \
    do {                                                                                                                                \
        display_release_G_display_member();                                                                                             \
        display_endwin();                                                                                                               \
    } while (0);                                                                                                                        \


/**
 * @brief 
 *  Handle TUI first page
 */
#define display_handle_TUI_first_page()                                                                                                                     \
    do                                                                                                                                                      \
    {                                                                                                                                                       \
        display_show_wins_0_1_2();                                                                                                                          \
        while (1)                                                                                                                                           \
        {                                                                                                                                                   \
            wmove(G_display.wins[2], 1, 1);                                                                                                                 \
            wattrset(G_display.wins[2], A_NORMAL);                                                                                                          \
            wclrtoeol(G_display.wins[2]);                                                                                                                   \
            wattrset(G_display.wins[2], A_BOLD);                                                                                                            \
            wattron(G_display.wins[2], COLOR_PAIR((3)));                                                                                                    \
            waddstr(G_display.wins[2], "Command: ");                                                                                                        \
            wattroff(G_display.wins[2], COLOR_PAIR((3)));                                                                                                   \
            wattron(G_display.wins[2], COLOR_PAIR((2)));                                                                                                    \
            box(G_display.wins[2], 0, 0);                                                                                                                   \
            wattroff(G_display.wins[2], COLOR_PAIR((2)));                                                                                                   \
            refresh();                                                                                                                                      \
            wrefresh(G_display.wins[2]);                                                                                                                    \
            int code = OK;                                                                                                                                  \
            char buffer[1008] = {0};                                                                                                                        \
            code = wgetnstr(G_display.wins[2], buffer, 1008);                                                                                               \
            TI("Code: %d; AND; Code: %x", code, code);                                                                                                      \
            if (display_G_sigwinch_flag)                                                                                                                    \
            {                                                                                                                                               \
                display_handle_win_resize(1);                                                                                                               \
                continue;                                                                                                                                   \
            }                                                                                                                                               \
            if (code == ERR)                                                                                                                                \
            {                                                                                                                                               \
                /* display_exit_TUI_showcase(); */                                                                                                          \
                TE("Called wgetnstr error");                                                                                                                \
                display_G_flag = 1;                                                                                                                         \
                break;                                                                                                                                      \
            }                                                                                                                                               \
            attroff(A_BOLD);                                                                                                                                \
            refresh();                                                                                                                                      \
            wrefresh(G_display.wins[2]);                                                                                                                    \
            mvwprintw(stdscr, 0, 0, "%s\n", buffer);                                                                                                        \
            refresh();                                                                                                                                      \
            wrefresh(stdscr);                                                                                                                               \
            if (!strncmp("Quit", buffer, 4))                                                                                                                \
            {                                                                                                                                               \
                /* display_exit_TUI_showcase(); */                                                                                                          \
                TI("Recv Quit String also exit");                                                                                                           \
                display_G_flag = 1;                                                                                                                         \
                break;                                                                                                                                      \
            }                                                                                                                                               \
            else                                                                                                                                            \
            {                                                                                                                                               \
                char cmd[1024] = {0};                                                                                                                       \
                snprintf(cmd, 1024, "%s", "netdump ");                                                                                                      \
                snprintf(cmd + strlen(cmd), (1024 - strlen(cmd)), "%s ", buffer);                                                                           \
                if (unlikely(((display_first_tui_handle_logic((const char *)(cmd),                                                                          \
                                                              G_display.wins[6], G_display.panels[6], G_display.wins[7], G_display.panels[7])) == ND_ERR))) \
                {                                                                                                                                           \
                    TE("Command error; need to again");                                                                                                     \
                    continue;                                                                                                                               \
                }                                                                                                                                           \
                break;                                                                                                                                      \
            }                                                                                                                                               \
        }                                                                                                                                                   \
        display_hide_wins_0_1_2();                                                                                                                          \
    } while (0);

/**
 * @brief 
 *  Select 3 windows
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
 * @brief 
 *  Select 4 windows
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
 * @brief 
 *  Select 5 windows  
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
 * @brief 
 *  Handle TUI second page
 */
#define display_handle_TUI_second_page()                                                                                                \
    do {                                                                                                                                \
        display_show_wins_3_4_5();                                                                                                      \
        display_set_wins_noecho_and_cbreak();                                                                                           \
        display_disable_cursor();                                                                                                       \
        int ch = 0;                                                                                                                     \
        unsigned char count = 0;                                                                                                        \
        while(1) {	                                                                                                                    \
            ch = getch();                                                                                                               \
            if (display_G_sigwinch_flag) {                                                                                              \
                display_handle_win_resize(2);                                                                                           \
                continue;                                                                                                               \
            }                                                                                                                           \
            if (ch == 80) {                                                                                                             \
                break;                                                                                                                  \
            }                                                                                                                           \
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
 * @brief 
 *  TUI processing entry
 */
#define display_TUI_processing_entry()                                                                                                  \
    do {                                                                                                                                \
        while (1) {                                                                                                                     \
            display_handle_TUI_first_page();                                                                                            \
            if (display_G_flag) break;                                                                                                  \
            display_handle_TUI_second_page();                                                                                           \
        }                                                                                                                               \
    } while (0);



/**
 * @brief
 *  Register sigwinch signal processing function
 */
#define display_regist_sigwinch_handle()                                                                                                \
    do {                                                                                                                                \
        signal(SIGWINCH, display_handle_winch_signal);                                                                                  \
    } while (0);                                                                                                                        \



/**
 * @brief 
 *  Startup TUI Showcase
 */
#define display_startup_TUI_showcase()                                                                                                  \
    do {                                                                                                                                \
        display_regist_sigwinch_handle();                                                                                               \
                                                                                                                                        \
        display_initialize_scr();                                                                                                       \
                                                                                                                                        \
        if (display_G_flag) goto label;                                                                                                 \
                                                                                                                                        \
        display_initialize_color();                                                                                                     \
                                                                                                                                        \
        if (display_G_flag) goto label;                                                                                                 \
                                                                                                                                        \
        display_check_term_size();                                                                                                      \
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
        if (display_G_flag) goto label;                                                                                                 \
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
                                                                                                                                        \
label:                                                                                                                                  \
        display_exit_TUI_showcase();                                                                                                    \
    } while (0);                                                                                                                        \


/**
 * @brief 
 *  TUI shows process exit resource destruction
 */
extern void display_exit_resource_destruction ();


#endif  // __DISPLAY_H__