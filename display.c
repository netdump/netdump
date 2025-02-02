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

#include "display.h"
#include "msgcomm.h"


/**
 * @brief The global flag of display tui, used to exit tui
 * @note
 * 	display_G_flag = 1; 
 * 	indicates an exception occurs and the system needs to exit
 */
unsigned char display_G_flag = 0;

/**
 * @brief 
 * 	Define a global variable to store the resources required by TUI
 * @note
 *  G_display.wins[0]: Netdump ASCII world
 *  G_display.wins[1]: Information of author
 *  G_display.wins[2]: Command input box
 *  G_display.wins[3]: Brief information display box
 *  G_display.wins[4]: Detailed information display box
 *  G_display.wins[5]: Original hexadecimal information display box
 *  G_display.panels[0]: The panel associated with G_display.wins[0]
 *  G_display.panels[1]: The panel associated with G_display.wins[1]
 *  G_display.panels[2]: The panel associated with G_display.wins[2]
 *  G_display.panels[3]: The panel associated with G_display.wins[3]
 *  G_display.panels[4]: The panel associated with G_display.wins[4]
 *  G_display.panels[5]: The panel associated with G_display.wins[5]
 */
display_t G_display = {
    {NULL, NULL, NULL, NULL, NULL, NULL, NULL},
    {NULL, NULL, NULL, NULL, NULL, NULL, NULL}
};


/**
 * @brief 
 * 	Format the title bar title
 * @param win: 
 * 	The window that is designated to format the input title
 * @param starty: 
 * 	The starting position of the title bar relative to the window's Y coordinate
 * @param startx: 
 * 	The starting position of the title bar relative to the window's X coordinate
 * @param width: 
 * 	Width of the title bar
 * @param string: 
 * 	Contents of the title bar
 * @param color: 
 * 	Color attribute of the title bar content
 */
int display_format_set_window_title(WINDOW *win, int starty, int startx, int width, char *string, chtype color) {

	TC("Called { %s (%p, %d, %d, %d, %s, %u)", __func__, win, starty, startx, width, string, color);

    int length, x, y;
	float temp;

	if(win == NULL)
		win = stdscr;

	getyx(win, y, x);

	if(startx != 0)
		x = startx;
	if(starty != 0)
		y = starty;
	if(width == 0)
		width = 80;

	length = strlen(string);
	temp = (width - length) / 2;
	x = startx + (int)temp;
	wattron(win, color);
	mvwprintw(win, y, x, "%s", string);
	wattroff(win, color);
	refresh();

	RInt(0);
}


/**
 * @brief 
 * 	TUI shows process exit resource destruction
 */
void display_exit_resource_destruction () {

	TC("called { %s", __func__);

	display_exit_TUI_showcase();

	RVoid();
}


/**
 * @brief 
 * 	The display process communicates with the capture process
 * @param command
 * 	Pointer to the message content
 * @return 
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int display_cmd_to_capture (const char * command) {

	TC("Called { %s()", __func__);

	if (unlikely((!command))) {
		T("errmsg: param error");
		RInt(ND_ERR);
	}

	if ( unlikely(
		((msgcomm_message_send(MSGCOMM_DIR_0TO1, MSGCOMM_CMD, command, strlen(command))) == ND_ERR)
	))
	{
		T("errmsg: msgcomm message send failed");
		RInt(ND_ERR);
	}

	RInt(ND_OK);
}


/**
 * @brief 
 * 	Receive messages from the capture process
 * @param message
 * 	Storing Messages
 * @return 
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int display_reply_from_capture (message_t * message) {

	TC("Called { %s(%p)", __func__, message);

	if (unlikely((!message))) {
        T("errmsg: param error");
        RInt(ND_ERR);
    }

    if (unlikely((msgcomm_message_recv(MSGCOMM_DIR_1TO0, message)) == ND_ERR)) {
        T("errmsg: msgcomm message recv failed");
        RInt(ND_ERR);
    }

	RInt(ND_OK);
}


/**
 * @brief 
 * 	Error message display
 * @param errmsg
 * 	error message
 * @param win
 * 	Error message display window
 * @param panel 
 * 	Error message window control panel
 * @return 
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
static void display_error_message_display (const char * errmsg, WINDOW * win, PANEL * panel) {

	TC("Called { %s(%s, %p, %p)", __func__, win, panel);

	show_panel(panel); 
	update_panels();
	doupdate();
	wmove(win, 1, 1);
	wattrset(win, A_NORMAL);
	wclrtoeol(win);
	wattrset(win, A_BOLD);
	wattron(win, COLOR_PAIR((4)));
	char space[1024] = {0};
	snprintf(space, 1024, "\nERRMSG:\n\t%s\n", errmsg);
	waddstr(win, space);
	wattroff(win, COLOR_PAIR((4)));
	wattron(win, COLOR_PAIR((4)));
	box(win, 0, 0);
	wattroff(win, COLOR_PAIR((4)));
	refresh();
	wrefresh(win);
	nd_delay_microsecond(3, 0);
	hide_panel(panel);
	update_panels();
	doupdate();
	RVoid();
} 


/**
 * @brief 
 * 	Display the processing logic interface of the first interface of the process
 * @param command
 * 	Commands entered via the tui interface
 * @param win
 * 	Error message display window
 * @param panel
 * 	Error message window control panel
 * @return 
 *  If successful, it returns ND_OK; 
 *  if failed, it returns ND_ERR
 */
int display_first_tui_handle_logic (const char * command, WINDOW * win, PANEL * panel) {

	TC("Called { %s(%s, %p, %p)", __func__, command, win, panel);

	if (unlikely((!command) || (!win) || (!panel))) {
		T("errmsg: param error; command: %p, win: %p, panel: %p", command, win, panel);
		RInt(ND_ERR);
	}

	if (unlikely(((display_cmd_to_capture(command))))) {
		T("errmsg: display cmd to capture failed");
		RInt(ND_ERR);
	}

	char space[1024] = {0};
	message_t * message = (message_t *)(space);
	if (unlikely(((display_reply_from_capture(message)) == ND_ERR))) {
		T("errmsg: display reply from capture failed");
		RInt(ND_ERR);
	}

	T("infomsg:     ");
	T("infomsg: message->dir: %u", message->dir);
	T("infomsg: message->msgtype: %u", message->msgtype);
	T("infomsg: message->length: %u", message->length);
	T("infomsg: message->msg: %s", message->msg);

	if (message->msgtype != MSGCOMM_SUC) {
		T("infomsg: %s", message->msg);
		display_error_message_display((const char *)(message->msg), win, panel);
		RInt(ND_ERR);
	}

	RInt(ND_OK);
}
