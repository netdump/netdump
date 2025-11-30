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
#include "a2d_comm.h"
#include "d2c_comm.h"


/**
 * @brief The global flag of display tui, used to exit tui
 * @note
 * 	display_exit_flag = 1; 
 * 	indicates an exception occurs and the system needs to exit
 */
volatile unsigned char display_exit_flag = 0;


/**
 * @brief
 * 	Whether the SIGWINCH signal is received
 * @note
 * 	The default initial value is 0
 * 	display_sigwinch_flag = 1;
 * 	After receiving the signal, display_sigwinch_flag is set to 1
 * 	display_sigwinch_flag = 0;
 * 	After redrawing the interface, display_sigwinch_flag is set to 0
 */
volatile unsigned char display_sigwinch_flag = 0;


/**
 * @brief
 * 	Stores the old values ​​of LINES
 */
volatile unsigned int display_old_lines = 0;


/**
 * @brief
 * 	Stores the old values ​​of COLS
 */
volatile unsigned int display_old_cols = 0;


/**
 * @brief
 * 	The number of lines that can be displayed in window 3/4/5
 */
volatile unsigned short display_win3_context_lines = 0;
volatile unsigned short display_win4_context_lines = 0;
volatile unsigned short display_win5_context_lines = 0;


/**
 * @brief
 * 	The number of cols that can be displayed in window 3/4/5
 */
volatile unsigned short display_win3_context_cols = 0;
volatile unsigned short display_win4_context_cols = 0;
volatile unsigned short display_win5_context_cols = 0;


/**
 * @brief
 * 	Define a global variable to store the resources required by TUI
 * @note
 *  display_resource.wins[0]: Netdump ASCII world
 *  display_resource.wins[1]: Information of author
 *  display_resource.wins[2]: Command input box
 *  display_resource.wins[3]: Brief information display box
 *  display_resource.wins[4]: Detailed information display box
 *  display_resource.wins[5]: Original hexadecimal information display box
 * 	display_resource.wins[6]: Display error message interface
 * 	display_resource.wins[7]: Display information after executing the command
 * 	display_resource.wins[8]: Display Captured packet information
 *  display_resource.panels[0]: The panel associated with display_resource.wins[0]
 *  display_resource.panels[1]: The panel associated with display_resource.wins[1]
 *  display_resource.panels[2]: The panel associated with display_resource.wins[2]
 *  display_resource.panels[3]: The panel associated with display_resource.wins[3]
 *  display_resource.panels[4]: The panel associated with display_resource.wins[4]
 *  display_resource.panels[5]: The panel associated with display_resource.wins[5]
 * 	display_resource.panels[6]: The panel associated with display_resource.wins[6]
 * 	display_resource.panels[7]: The panel associated with display_resource.wins[7]
 * 	display_resource.panels[8]: The panel associated with display_resource.wins[8]
 */
display_t display_resource = {
    {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL},
    {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL}
};


/**
 * @brief
 * 	[win 5] specifies the byte offset in the content line [hex] [char]
 * 	byte index from 0 to 15
 * @param hex_offset hexadecimal offset
 * @param char_offset character offset
 */
typedef struct content_line_hex_char_offset_s 
{
	unsigned char hex_offset_start;
	unsigned char hex_offset_tail;
	unsigned char char_offset;
	unsigned char padding;
} content_line_hex_char_offset_t;

#define CLHCO_NUMBER											(16U)

content_line_hex_char_offset_t clhco[CLHCO_NUMBER] = {
	{12, 13, 54, 0}, {14, 15, 55, 0}, {17, 18, 56, 0}, {19, 20, 57, 0},
	{22, 23, 58, 0}, {24, 25, 59, 0}, {27, 28, 60, 0}, {29, 30, 61, 0},
	{32, 33, 62, 0}, {34, 35, 63, 0}, {37, 38, 64, 0}, {39, 40, 65, 0},
	{42, 43, 66, 0}, {44, 45, 67, 0}, {47, 48, 68, 0}, {49, 50, 69, 0}
};


/**
 * @brief
 * 	display the previous head, tail, and current value of the linked list
 * 	the following variables are related to window 3
 */
static volatile nd_dll_t *display_previous_head = NULL;
static volatile nd_dll_t *display_previous_tail = NULL;
static volatile nd_dll_t *display_previous_current = NULL;
static volatile unsigned short display_previous_cur_index = 0xDFFF;


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
int display_cmd_to_capture (char * command) {

	TC("Called { %s()", __func__);

	if (unlikely((!command))) {
		TE("param error; command: %s", command);
		RInt(ND_ERR);
	}

	if (unlikely(((d2c_comm_send_msg_2_capture(command)) == ND_ERR)))
	{
		TE("msgcomm message send failed");
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
int display_reply_from_capture(desc_comm_msg_t *message)
{
	TC("Called { %s(%p)", __func__, message);

	if (unlikely((!message))) {
        TE("param error; message: %p", message);
        RInt(ND_ERR);
    }

	if (unlikely((d2c_comm_recv_msg_from_capture(message)) == ND_ERR))
	{
		TE("msgcomm message recv failed");
        RInt(ND_ERR);
	}

	RInt(ND_OK);
}

/**
 * @brief 
 * 	Error message display
 * @param prefix
 * 	message prefix
 * @param msg
 * 	message
 * @param win
 * 	message display window
 * @param panel 
 * 	message window control panel
 * @param color
 * 	color pair
 */
static void display_message_display (const char * prefix, const char * msg, WINDOW * win, PANEL * panel, int color) {

	TC("Called { %s(%s, %s, %p, %p, %d)", __func__, prefix, msg, win, panel, color);

	show_panel(panel); 
	update_panels();
	doupdate();
	wmove(win, 2, 3);
	wattrset(win, A_NORMAL);
	wclrtoeol(win);
	wattrset(win, A_BOLD);
	wattron(win, COLOR_PAIR((color)));
	memset(d2c_comm.store_hint_info, 0, COMM_SHM_ZONE_SIZE);
	snprintf(d2c_comm.store_hint_info, COMM_SHM_ZONE_SIZE, "%s\n\t%s\n", prefix, msg);
	waddstr(win, d2c_comm.store_hint_info);
	wattroff(win, COLOR_PAIR((color)));
	wattron(win, COLOR_PAIR((color)));
	box(win, 0, 0);
	wattroff(win, COLOR_PAIR((color)));
	refresh();
	wrefresh(win);
	getchar();
	wclear(win);
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
int display_first_tui_handle_logic(char *command, WINDOW *errwin, PANEL *errpanel, WINDOW *infowin, PANEL *infopanel)
{

	TC("Called { %s(%s, %p, %p)", __func__, command, errwin, errpanel);

	if (unlikely((!command) || (!errwin) || (!errpanel) || (!infowin) || (!infopanel)))
	{
		TE("param error; command: %s, errwin: %p, errpanel: %p, infowin: %p, infopanel: %p", 
			command, errwin, errpanel, infowin, infopanel);
		RInt(ND_ERR);
	}

	int count = 0, i = 0, len = strlen(command);
	for (i = 0; i < len; i++)
	{
		if (command[i] == '-')
		{
			count++;
		}
	}
	if (!count)
	{
		display_message_display("ERROR MSG:", "Missing '-' character", errwin, errpanel, 4);
		RInt(ND_ERR);
	}

	if (unlikely(((display_cmd_to_capture(command))))) {
		TE("display cmd to capture failed");
		RInt(ND_ERR);
	}

	desc_comm_msg_t message;
	if (unlikely(((display_reply_from_capture(&message)) == ND_ERR))) {
		TE("display reply from capture failed");
		RInt(ND_ERR);
	}

	TI("     ");
	TI("message.direction: %u", message.direction);
	TI("message.msgtype: %u", message.msgtype);
	TI("message.length: %u", message.length);
	TI("message.content: %s", message.content);

	if (message.msgtype == D2C_COMM_ERR) {
		TI("%s", message.content);
		display_message_display("ERROR MSG:", (const char *)(message.content), errwin, errpanel, 4);
		RInt(ND_ERR);
	}
	else if (message.msgtype == D2C_COMM_HLP)
	{
		display_message_display("HELP MSG:", (const char *)(message.content), infowin, infopanel, 5);
		RInt(ND_ERR);
	}
	else if (message.msgtype == D2C_COMM_FAD)
	{
		display_message_display("ALLDEVICE MSG:", (const char *)(message.content), infowin, infopanel, 5);
		RInt(ND_ERR);
	}
	else if (message.msgtype == D2C_COMM_DLT)
	{
		display_message_display("DATA-LINK-TYPE MSG:", (const char *)(message.content), infowin, infopanel, 5);
		RInt(ND_ERR);
	}
	else if (message.msgtype == D2C_COMM_SUC)
	{
		memset(d2c_comm.store_capture_info, 0, COMM_SHM_ZONE_SIZE);
		snprintf(d2c_comm.store_capture_info, COMM_SHM_ZONE_SIZE, "%s", (message.content));
	}

	RInt(ND_OK);
}


/**
 * @brief
 * 	sigwinch signal processing function
 * @param signum
 * 	Signal number
 */
void display_handle_winch_signal (int signum) {

	TC("Called { %s(%d)", __func__, signum);

	display_sigwinch_flag = 1;

	RVoid();
}


/**
 * @brief
 * 	dump size infomation
 */
void diaplay_dump_size_info(void)
{

	TC("Called { %s(void)", __func__);

	TI("LINES: %d; COLS: %d\n", LINES, COLS);

	TI("DISPLAY_WINS_0_NYBEGIN: %d; DISPLAY_WINS_0_NXBEGIN: %d", DISPLAY_WINS_0_NYBEGIN, DISPLAY_WINS_0_NXBEGIN);
	TI("DISPLAY_WINS_0_NLINES: %d; DISPLAY_WINS_0_NCOLS: %d", DISPLAY_WINS_0_NLINES, DISPLAY_WINS_0_NCOLS);
	TI("DISPLAY_WINS_1_NYBEGIN: %d; DISPLAY_WINS_1_NXBEGIN: %ld", DISPLAY_WINS_1_NYBEGIN, DISPLAY_WINS_1_NXBEGIN);
	TI("DISPLAY_WINS_1_NLINES: %d; DISPLAY_WINS_1_NCOLS: %ld", DISPLAY_WINS_1_NLINES, DISPLAY_WINS_1_NCOLS);
	TI("DISPLAY_WINS_2_NYBEGIN: %d; DISPLAY_WINS_2_NXBEGIN: %d", DISPLAY_WINS_2_NYBEGIN, DISPLAY_WINS_2_NXBEGIN);
	TI("DISPLAY_WINS_2_NLINES: %d; DISPLAY_WINS_2_NCOLS: %d", DISPLAY_WINS_2_NLINES, DISPLAY_WINS_2_NCOLS);
	TI("DISPLAY_WINS_3_NYBEGIN: %d; DISPLAY_WINS_3_NXBEGIN: %d", DISPLAY_WINS_3_NYBEGIN, DISPLAY_WINS_3_NXBEGIN);
	TI("DISPLAY_WINS_3_NLINES: %d; DISPLAY_WINS_3_NCOLS: %d", DISPLAY_WINS_3_NLINES, DISPLAY_WINS_3_NCOLS);
	TI("DISPLAY_WINS_4_NYBEGIN: %d; DISPLAY_WINS_4_NXBEGIN: %d", DISPLAY_WINS_4_NYBEGIN, DISPLAY_WINS_4_NXBEGIN);
	TI("DISPLAY_WINS_4_NLINES: %d; DISPLAY_WINS_4_NCOLS: %d", DISPLAY_WINS_4_NLINES, DISPLAY_WINS_4_NCOLS);
	TI("DISPLAY_WINS_5_NYBEGIN: %d; DISPLAY_WINS_5_NXBEGIN: %d", DISPLAY_WINS_5_NYBEGIN, DISPLAY_WINS_5_NXBEGIN);
	TI("DISPLAY_WINS_5_NLINES: %d; DISPLAY_WINS_5_NCOLS: %d", DISPLAY_WINS_5_NLINES, DISPLAY_WINS_5_NCOLS);
	TI("DISPLAY_WINS_6_NYBEGIN: %d; DISPLAY_WINS_6_NXBEGIN: %d", DISPLAY_WINS_6_NYBEGIN, DISPLAY_WINS_6_NXBEGIN);
	TI("DISPLAY_WINS_6_NLINES: %d; DISPLAY_WINS_6_NCOLS: %d", DISPLAY_WINS_6_NLINES, DISPLAY_WINS_6_NCOLS);
	TI("DISPLAY_WINS_7_NYBEGIN: %d; DISPLAY_WINS_7_NXBEGIN: %d", DISPLAY_WINS_7_NYBEGIN, DISPLAY_WINS_7_NXBEGIN);
	TI("DISPLAY_WINS_7_NLINES: %d; DISPLAY_WINS_7_NCOLS: %d", DISPLAY_WINS_7_NLINES, DISPLAY_WINS_7_NCOLS);
	TI("DISPLAY_WINS_8_NYBEGIN: %d; DISPLAY_WINS_8_NXBEGIN: %d", DISPLAY_WINS_8_NYBEGIN, DISPLAY_WINS_8_NXBEGIN);
	TI("DISPLAY_WINS_8_NLINES: %d; DISPLAY_WINS_8_NCOLS: %d", DISPLAY_WINS_8_NLINES, DISPLAY_WINS_8_NCOLS);

	RVoid();
}

/**
 * @brief
 * 	Redraw the interface after the interface size changes
 * @param flag
 * 	Flags for the first TUI interface and the second TUI interface
 * 	flag = 1 indicates the first TUI interface
 * 	flag = 2 indicates the second TUI interface
 */
void display_handle_win_resize(int flag) {

	TC("Called { %s(void)", __func__);

	int i = 0;

	display_sigwinch_flag = 0;

	display_hide_wins_all();

	werase(stdscr);

	for (i = 0; i < (display_pw_number - 1); i++)
	{
		werase(display_resource.wins[i]);
	}

	erase();

	for (i = 0; i < (display_pw_number - 1); i++)
	{
		del_panel(display_resource.panels[i]);
		update_panels();
		display_resource.panels[i] = NULL;
	}

	for (i = 0; i < (display_pw_number - 1); i++)
	{
		if (display_resource.wins[i])
		{
			delwin(display_resource.wins[i]);
			display_resource.wins[i] = NULL;
		}
	}

	display_check_term_size();

	struct winsize w;

	for (i = 0; i < 6; i++)
	{
		ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
		if (w.ws_col == display_old_cols && w.ws_row == display_old_lines)
		{
			TI("i: %d; w.ws_col == display_old_cols and w.ws_row == display_old_lines", i);
			continue;
		}
		TI("i: %d; display_old_cols: %d; display_old_lines: %d", i, display_old_cols, display_old_lines);
		display_old_cols = w.ws_col;
		display_old_lines = w.ws_row;
		TI("i: %d; display_old_cols: %d; display_old_lines: %d", i, display_old_cols, display_old_lines);
		TI("i: %d; w.ws_col: %d; w.ws_row: %d", i, w.ws_col, w.ws_row);
	}

	resizeterm(w.ws_row, w.ws_col);

	if (LINES == w.ws_row && w.ws_col == COLS)
	{
		TI("Resize SUC");
	}
	else
	{
		TI("Resize FAIL");
	}

	display_apply_first_tui_wins_resources();
	display_apply_second_tui_wins_resources();

	display_apply_first_tui_panels_resources();
	display_apply_second_tui_panels_resources();

	update_panels();
	doupdate();

	display_draw_netdump_ASCII_world();

	display_draw_author_information();

	display_draw_cmd_input_box();

	display_draw_brief_information_box();

	display_draw_more_information_box();

	display_draw_raw_information_box();

	display_draw_cpinfo_win();

	wnoutrefresh(stdscr);
	for (i = 0; i < (display_pw_number - 1); i++)
	{
		wnoutrefresh(display_resource.wins[1]);
	}

	display_hide_wins_all();

	if (flag == 1)
	{

		display_hide_wins_3_4_5();
		display_show_wins_0_1_2();
	}
	else if (flag == 2)
	{

		display_hide_wins_0_1_2();
		display_show_wins_3_4_5();
	}

	display_win3_context_lines = ((DISPLAY_WINS_3_NLINES) - 4);
	display_win4_context_lines = ((DISPLAY_WINS_4_NLINES) - 2);
	display_win5_context_lines = ((DISPLAY_WINS_5_NLINES) - 2);
	display_win3_context_cols = ((DISPLAY_WINS_3_NCOLS) - 2);
	display_win4_context_cols = ((DISPLAY_WINS_4_NCOLS) - 2);
	display_win5_context_cols = ((DISPLAY_WINS_5_NCOLS) - 2);
	a2d_info.w3_displayed_max_lines = display_win3_context_lines;

	RVoid();
}

/**
 * @brief
 * 	Detection terminal size
 */
void display_check_term_size(void) 
{

	TC("Called { %s(void)", __func__);

	int i = 0;
	struct winsize w;

	if (LINES >= DISPLAY_EXPECT_TERMINAL_LINES && COLS >= DISPLAY_EXPECT_TERMINAL_COLS)
	{
		RVoid();
	}

	for (i = 0; i < 3; i++) {
		ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
		if (w.ws_row < DISPLAY_EXPECT_TERMINAL_LINES || w.ws_col < DISPLAY_EXPECT_TERMINAL_COLS){
			wclear(stdscr);
			refresh();
			wmove(stdscr, (w.ws_row / 2), 0);
			wattrset(stdscr, A_NORMAL);
			wclrtoeol(stdscr);
			wattrset(stdscr, A_BOLD);
			wattron(stdscr, COLOR_PAIR((4)));
			char space[512] = {0};
			snprintf(space, 512, "\t[%d]\n\tPlease adjust the size of the terminal;"
								 "\n\tafter three prompts, the program will exit."
								 "\n\tYou can modify the terminal font size, "
								 "\n\tOr drag the terminal to a larger screen.",
					 (i + 1));
			waddstr(stdscr, space);
			wattroff(stdscr, COLOR_PAIR((4)));
			wattron(stdscr, COLOR_PAIR((4)));
			box(stdscr, 0, 0);
			wattroff(stdscr, COLOR_PAIR((4)));
			refresh();
			wrefresh(stdscr);
			getchar();
			wclear(stdscr);
		}
		else {
			TI("To meet the requirements of terminal size");
			resizeterm(w.ws_row, w.ws_col);
			RVoid();
		}
	}

	TE("The terminal size does not meet the requirements; Kill Will be Called");
	kill(getpid(), 15);

	RVoid();
}


static int display_resource_second_cur_win = 0;

/**
 * @brief
 * 	The execution logic of the second TUI interface
 */
void display_second_tui_exec_logic (void) {

	TC("Called { %s(void)", __func__);

	display_show_wins_3_4_5();
	display_draw_cpinfo_win();
	display_clear_content_line();
	display_set_wins_noecho_and_cbreak();
	display_start_or_close_timeout(1000);
	display_disable_cursor();
	unsigned int ch = 0;
	unsigned char count = 0;
	a2d_reset_a2dinfo_flag();

	display_previous_head = NULL;
	display_previous_tail = NULL;
	display_previous_current = NULL;
	display_previous_cur_index = 0xDFFF;
	display_resource_second_cur_win = 3;

	#if 1
	__atomic_store_n(&(d2c_statistical_count.bytes), 0, __ATOMIC_SEQ_CST);
	__atomic_store_n(&(d2c_statistical_count.packages), 0, __ATOMIC_SEQ_CST);
	__atomic_store_n(&(d2c_run_flag.d2c_run_flag_val), 0, __ATOMIC_SEQ_CST);
	__atomic_store_n(&(d2c_run_flag.c2d_run_flag_val), 0, __ATOMIC_SEQ_CST);
#endif

	while (1)
	{
		flushinp();
		ch = getch();
		if (display_sigwinch_flag)
		{
			display_handle_win_resize(2);
			continue;
		}

		unsigned int tmp = __atomic_load_n(&(d2c_run_flag.c2d_run_flag_val), __ATOMIC_SEQ_CST);
		if (tmp == C2D_RUN_FLAG_FD_ERR ||
			tmp == C2D_RUN_FLAG_PCAP_BREAKLOOP_ERR ||
			tmp == C2D_RUN_FLAG_PCAP_DISPATCH_ERR ||
			tmp == C2D_RUN_FLAG_POLL_ERR)
		{
			TE("Capture Process Error; ErrCode: %hu", tmp);
			break;
		}

		if ('q' == ch) 
		{
			TI("ch: %u", ch);
			__atomic_store_n(&(d2c_run_flag.d2c_run_flag_val), C2D_RUN_FLAG_EXIT, __ATOMIC_SEQ_CST);
			// Whether the CP process needs to return the exit status
			break;
		}
		else if ('s' == ch) 
		{
			TI("ch: %u", ch);
			__atomic_store_n(&(d2c_run_flag.d2c_run_flag_val), C2D_RUN_FLAG_SAVE, __ATOMIC_SEQ_CST);
			// Pop-up prompt window & Check whether the data is saved
			// This feature is not implemented.
			break;
		}
		switch (ch)
		{
			case 9:
				TI("ch: %u; count: %d", ch, count);
				switch (((count % 3) + 3))
				{
					case 3:
						display_select_3_windows();
						display_resource_second_cur_win = 3;
						break;
					case 4:
						display_select_4_windows();
						display_resource_second_cur_win = 4;
						break;
					case 5:
						display_select_5_windows();
						display_resource_second_cur_win = 5;
						break;
					default:
						break;
				}
				count++;
				break;
			case 'p':
				TI("ch: %u", ch);
				__atomic_store_n(&(d2c_run_flag.d2c_run_flag_val), C2D_RUN_FLAG_PAUSE, __ATOMIC_SEQ_CST);
				break;
			case 'c':
				TI("ch: %u", ch);
				__atomic_store_n(&(d2c_run_flag.d2c_run_flag_val), C2D_RUN_FLAG_CONTINUE, __ATOMIC_SEQ_CST);
				break;
			case KEY_UP:
				TI("ch: %u; KEY_UP: %u; display_resource_second_cur_win: %d", ch, KEY_UP, display_resource_second_cur_win);
				display_move_up_selected_content(display_resource_second_cur_win);
				break;
			case KEY_DOWN:
				TI("ch: %u; KEY_DOWN: %u; display_resource_second_cur_win: %d", ch, KEY_DOWN, display_resource_second_cur_win);
				display_move_down_selected_content(display_resource_second_cur_win);
				break;
			case KEY_ENTER:
				;__attribute__((fallthrough));
			case '\n':;
				;__attribute__((fallthrough));
			case '\r':
				TI("ch: %u; KEY_ENTER: %u; display_resource_second_cur_win: %d", ch, KEY_ENTER, display_resource_second_cur_win);
				display_exec_enter_behavior(display_resource_second_cur_win);
				break;
			default:
				break;
		}
		if (
			display_previous_head != a2d_info.w3_displayed_list_head ||
			display_previous_tail != a2d_info.w3_displayed_list_tail ||
			display_previous_current != a2d_info.w3_displayed_cur_node)
		{
			display_content_to_the_interface(a2d_info.w3_displayed_list_head);
			display_previous_head = a2d_info.w3_displayed_list_head;
			display_previous_tail = a2d_info.w3_displayed_list_tail;
			display_previous_current = a2d_info.w3_displayed_cur_node;
			display_previous_cur_index = a2d_info.w3_displayed_cur_index;
		}
		a2d_info.displayed_status_flag = A2D_DISPLAYED;
		//display_draw_cpinfo_win();
	}

	display_hide_wins_3_4_5();
	display_start_or_close_timeout(0);
	display_set_wins_echo_and_nocbreak();
	display_enable_cursor();

	RVoid();
}


/**
 * @brief
 * 	Clear the line showing the content in window 3
 */
void display_clear_content_line (void)
{
	TC("Called { %s (void)", __func__);

	DISPLAY_WIN_3_CONTENT_CLEAR();

	DISPLAY_WIN_4_CONTENT_CLEAR();

	DISPLAY_WIN_5_CONTENT_CLEAR();

	RVoid();
}


/**
 * @brief
 * 	Display content to the interface
 * @memberof head
 * 	display dll head
 */
void display_content_to_the_interface(nd_dll_t * head)
{
	//TC("Called { %s (%p)", __func__, head);

	if (!a2d_info.w3_displayed_cur_node_nums || !head)
		return ;

	int i = 0;
	nd_dll_t * node = head;
	infonode_t * infonode = NULL;

	while (a2d_info.analysis_status_flag == A2D_ANALYSISING);

	a2d_info.displayed_status_flag = A2D_DISPLAYING;

	/* window 3 display */
	if (
		display_previous_head != a2d_info.w3_displayed_list_head || 
		display_previous_tail != a2d_info.w3_displayed_list_tail
	)
	{
		for (i = 0; i < a2d_info.w3_displayed_cur_node_nums; i++)
		{
			infonode = container_of(node, infonode_t, listnode);

			if (node == a2d_info.w3_displayed_cur_node)
				wattron(display_resource.wins[3], COLOR_PAIR(5));
			else 
				if (i % 2)
					wattron(display_resource.wins[3], COLOR_PAIR(7));
				else
					wattron(display_resource.wins[3], COLOR_PAIR(8));

			wmove(display_resource.wins[3], (i + 3), 1);
			wprintw(display_resource.wins[3], "%*s", (COLS - 2), "");
			if (node == a2d_info.w3_displayed_cur_node)
				mvwprintw(display_resource.wins[3], (i + 3), 1, "%c", '>');
			mvwprintw(display_resource.wins[3], (i + 3), START_X_TIME, "%s", infonode->timestamp);
			mvwprintw(display_resource.wins[3], (i + 3), START_X_SRCADDR, "%s", infonode->srcaddr);
			mvwprintw(display_resource.wins[3], (i + 3), START_X_DSTADDR, "%s", infonode->dstaddr);
			mvwprintw(display_resource.wins[3], (i + 3), START_X_PROTOCOL, "%s", infonode->protocol);
			mvwprintw(display_resource.wins[3], (i + 3), START_X_DATALENGTH, "%s", infonode->length);
			mvwprintw(display_resource.wins[3], (i + 3), START_X_BRIEF, "%s", infonode->brief);

			if (node == a2d_info.w3_displayed_cur_node)
				wattroff(display_resource.wins[3], COLOR_PAIR(5));
			else 
				if (i % 2)
					wattroff(display_resource.wins[3], COLOR_PAIR(7));
				else
					wattroff(display_resource.wins[3], COLOR_PAIR(8));

			node = node->next;
			if (!node)
				break;
		}
	}
	else 
	{
		if (display_previous_current != a2d_info.w3_displayed_cur_node)
		{

			infonode = container_of(display_previous_current, infonode_t, listnode);
			if (display_previous_cur_index % 2)
				wattron(display_resource.wins[3], COLOR_PAIR(7));
			else
				wattron(display_resource.wins[3], COLOR_PAIR(8));

			wmove(display_resource.wins[3], (display_previous_cur_index + 3), 1);
			wprintw(display_resource.wins[3], "%*s", (COLS - 2), "");
			mvwprintw(display_resource.wins[3], (display_previous_cur_index + 3), START_X_TIME, "%s", infonode->timestamp);
			mvwprintw(display_resource.wins[3], (display_previous_cur_index + 3), START_X_SRCADDR, "%s", infonode->srcaddr);
			mvwprintw(display_resource.wins[3], (display_previous_cur_index + 3), START_X_DSTADDR, "%s", infonode->dstaddr);
			mvwprintw(display_resource.wins[3], (display_previous_cur_index + 3), START_X_PROTOCOL, "%s", infonode->protocol);
			mvwprintw(display_resource.wins[3], (display_previous_cur_index + 3), START_X_DATALENGTH, "%s", infonode->length);
			mvwprintw(display_resource.wins[3], (display_previous_cur_index + 3), START_X_BRIEF, "%s", infonode->brief);

			if (display_previous_cur_index % 2)
				wattroff(display_resource.wins[3], COLOR_PAIR(7));
			else
				wattroff(display_resource.wins[3], COLOR_PAIR(8));

			
			infonode = container_of(a2d_info.w3_displayed_cur_node, infonode_t, listnode);
			wattron(display_resource.wins[3], COLOR_PAIR(5));

			wmove(display_resource.wins[3], (a2d_info.w3_displayed_cur_index + 3), 1);
			wprintw(display_resource.wins[3], "%*s", (COLS - 2), "");
			mvwprintw(display_resource.wins[3], (a2d_info.w3_displayed_cur_index + 3), 1, "%c", '>');
			mvwprintw(display_resource.wins[3], (a2d_info.w3_displayed_cur_index + 3), START_X_TIME, "%s", infonode->timestamp);
			mvwprintw(display_resource.wins[3], (a2d_info.w3_displayed_cur_index + 3), START_X_SRCADDR, "%s", infonode->srcaddr);
			mvwprintw(display_resource.wins[3], (a2d_info.w3_displayed_cur_index + 3), START_X_DSTADDR, "%s", infonode->dstaddr);
			mvwprintw(display_resource.wins[3], (a2d_info.w3_displayed_cur_index + 3), START_X_PROTOCOL, "%s", infonode->protocol);
			mvwprintw(display_resource.wins[3], (a2d_info.w3_displayed_cur_index + 3), START_X_DATALENGTH, "%s", infonode->length);
			mvwprintw(display_resource.wins[3], (a2d_info.w3_displayed_cur_index + 3), START_X_BRIEF, "%s", infonode->brief);

			wattroff(display_resource.wins[3], COLOR_PAIR(5));
		}
	}

	if (display_previous_current != a2d_info.w3_displayed_cur_node)
	{
		/* window 4 display */

		DISPLAY_WIN_4_CONTENT_CLEAR();

		int i = 0;
		infonode = container_of(a2d_info.w3_displayed_cur_node, infonode_t, listnode);

		if (!(infonode->l1l2head)) {
			TE("fatal logic error; infonode->l1l2head: %p", infonode->l1l2head);
			abort();
		}

		l1l2_node_t * l1l2h = container_of(infonode->l1l2head, l1l2_node_t, l1l2node);

		a2d_info.w4_l1l2_node_list_head = l1l2h;
		a2d_info.w4_l1l2_node_cur_node = l1l2h;
		a2d_info.w4_l1l2_node_cur_line = 1;

		unsigned short rows_num = a2d_info.w4_l1l2_node_cur_line;
		l1l2_node_t * tmp = a2d_info.w4_l1l2_node_list_head;

		for (i = 0; i < display_win4_context_lines; i++)
		{
			if (!tmp) break;

			a2d_info.w4_l1l2_node_list_tail = tmp;

			if (rows_num == a2d_info.w4_l1l2_node_cur_line)
				wattron(display_resource.wins[4], COLOR_PAIR(5));
			else
				wattroff(display_resource.wins[4], COLOR_PAIR(5));

			if (tmp->level == 1) {
				if (tmp->isexpand == 1) {
					DISPLAY_WIN_DISPLAY_CONTENT_WITH_SPECIFYING_CHAR(
						display_resource.wins[4], rows_num, 2, display_win4_context_cols, '-', "%s", tmp->content);
					tmp = container_of((tmp->l1l2node.next), l1l2_node_t, l1l2node);
					if (!tmp) {
						TE("fatal logic error;");
						abort();
					}
					continue;
				}
				else if (tmp->isexpand == 0) {
					DISPLAY_WIN_DISPLAY_CONTENT_WITH_SPECIFYING_CHAR(
						display_resource.wins[4], rows_num, 2, display_win4_context_cols, '+', "%s", tmp->content);

					if (tmp->l1node.next == NULL)
					{
						TI("win4 output complete");
						break;
					}

					tmp = container_of((tmp->l1node.next), l1l2_node_t, l1node);
					continue;						
				}
				else {
					TE("fatal logic error; tmp: %p; tmp->level: %d; tmp->isexpand: %d", tmp, tmp->level, tmp->isexpand);
					abort();
				}
			}

			if (tmp->level == 2) {
				#if 0
				if (tmp->byte_start || tmp->byte_end) {
					TE("fatal logic error; tmp: %p; tmp->content: %s; tmp->byte_start: %d, tmp->byte_end: %d", 
						tmp, tmp->content, tmp->byte_start, tmp->byte_end);
					exit(1);
				}
				#endif
				DISPLAY_WIN_DISPLAY_CONTENT(
					display_resource.wins[4], rows_num, 2, display_win4_context_cols, "%s", tmp->content);

				if (tmp->l1l2node.next == NULL)
				{
					TI("win4 output complete");
					break;
				}

				tmp = container_of((tmp->l1l2node.next), l1l2_node_t, l1l2node);
			}

		}

		/* window 5 display */
		DISPLAY_WIN_5_CONTENT_CLEAR();
		
		if (!(infonode->w5head)) {
			TE("fatal logic error; infonode->w5head: %p", infonode->w5head);
			abort();
		}
		w5_node_t * w5 = NULL, * w5tmp = NULL;
		w5 = container_of(infonode->w5head, w5_node_t, w5node);

		a2d_info.w5_displayed_cur_line_number = rows_num = 1;
		a2d_info.w5_displayed_start_byte_index = w5->startindex;
		a2d_info.w5_displayed_end_byte_index = 0;
		a2d_info.w5_displayed_list_head = w5tmp = w5;
		a2d_info.w5_displayed_cur_node = w5;

		for (i = 0; i < display_win5_context_lines; i++)
		{
			if (!w5tmp) break;
			a2d_info.w5_displayed_list_tail = w5tmp;

			if (w5tmp == a2d_info.w5_displayed_cur_node)
				wattron(display_resource.wins[5], COLOR_PAIR(5));
			else
				wattroff(display_resource.wins[5], COLOR_PAIR(5));

			mvwprintw(display_resource.wins[5], (rows_num + i), 1, "%s", w5tmp->content);

			if (!(w5tmp->w5node.next)) {
				TI("win5 output complete");
				break;
			}

			w5tmp = container_of((w5tmp->w5node.next), w5_node_t, w5node);
		}

		a2d_info.w5_displayed_end_byte_index = a2d_info.w5_displayed_list_tail->endindex;
	}
	
	wrefresh(display_resource.wins[3]);
	wrefresh(display_resource.wins[4]);
	wrefresh(display_resource.wins[5]);

	//RVoid();
	return ;
}


/**
 * @brief
 * 	window 3 move selection up
 */
void display_win_3_move_up_selected_content (void)
{
	//TC("Called { %s(void)", __func__);

	if (!a2d_info.w3_displayed_cur_node)
		return ;

	a2d_info.is_manual_flag = A2D_MANUAL;
	
	nd_dll_t *node = a2d_info.w3_displayed_cur_node;
	infonode_t *infonode = container_of(node, infonode_t, listnode);

	TI("infonode->g_store_index: %lu", infonode->g_store_index);

	if (infonode->g_store_index == 0) {
		display_popup_message_notification("It's already at the top");
		//RVoid();
		return ;
	}

	if (a2d_info.w3_displayed_cur_index == 0) {
		a2d_info.is_manual_flag = A2D_MANUAL_TOP;
		nd_delay_microsecond(0, 1000000);
		//RVoid();
		return ;
	}

	a2d_info.w3_displayed_cur_node = node->prev;
	a2d_info.w3_displayed_cur_index--;

	//RVoid();
	return ;
}


/** define display_win_5_redraw_interface */
void display_win_5_redraw_interface(w5_node_t * newhead, w5_node_t * cur, int line);

/**
 * @brief
 * 	win4 clears the color of the curline area of win5
 */
#define DISPLAY_WIN4_CLEAR_WIN5_CURLINE_COLOR()																\
	do {																									\
		wmove(display_resource.wins[5], a2d_info.w5_displayed_cur_line_number, 1);												\
		wprintw(display_resource.wins[5], "%*s", display_win5_context_cols, "");									\
		mvwprintw(display_resource.wins[5], a2d_info.w5_displayed_cur_line_number, 1, "%s", a2d_info.w5_displayed_cur_node->content);		\
	} while(0);																								\


/**
 * @brief
 * 	win4 clears the color of the specified area of ​​win5
 * @param l1l2node win4 specified node
 */
void display_win4_clear_win5_specified_area_color(l1l2_node_t * l1l2node)
{
	TC("Called { %s(%p)", __func__, l1l2node);

	if (!l1l2node) 
	{
		TE("param error; l1l2node: %p", l1l2node);
		abort();
	}

	if (l1l2node->byte_start > INFONODE_BYTE_START_MAX || l1l2node->byte_end > INFONODE_BYTE_END_MAX
		|| l1l2node->byte_start < 0 || l1l2node->byte_end < 0)
	{
		TE("byte_start or byte_end is problems; l1l2node->byte_start: %d; l1l2node->byte_end: %d",
		   l1l2node->byte_start, l1l2node->byte_end);
		abort();
	}

	if (l1l2node->byte_start == 0 && l1l2node->byte_end == 0)
		RVoid();

	if (l1l2node->byte_start < a2d_info.w5_displayed_start_byte_index)
	{
		w5_node_t * tmp_w5_head = a2d_info.w5_displayed_list_head;
		unsigned short tmp_w5_start_byte_index = a2d_info.w5_displayed_start_byte_index;
		while (l1l2node->byte_start < tmp_w5_start_byte_index)
		{
			if (!(tmp_w5_head->w5node.prev))
			{
				TE("a fatal error occurred; l1l2node: %p; l1l2node->byte_start: %d; tmp_w5_start_byte_index: %hu",
				l1l2node, l1l2node->byte_start, tmp_w5_start_byte_index);
				abort();
			}

			tmp_w5_head = container_of(tmp_w5_head->w5node.prev, w5_node_t, w5node);
			tmp_w5_start_byte_index = tmp_w5_head->startindex;
		}

		display_win_5_redraw_interface(tmp_w5_head, tmp_w5_head, 1);
	}

	DISPLAY_WIN4_CLEAR_WIN5_CURLINE_COLOR();

	w5_node_t * byte_start = NULL, * tmp = NULL;
	unsigned short byte_start_index = 0, tmp_index = 1;

	for (tmp_index = 1, tmp = a2d_info.w5_displayed_list_head; tmp_index <= display_win5_context_lines; tmp_index++)
	{
		if (l1l2node->byte_start >= tmp->startindex && l1l2node->byte_start <= tmp->endindex) 
		{
			byte_start = tmp;
			byte_start_index = tmp_index;
			break;
		}
		if (!(tmp->w5node.next)) 
		{
			TE("a fatal error occurred; l1l2node: %p; l1l2node->byte_start: %d;", l1l2node, l1l2node->byte_start);
			abort();
		}
		tmp = container_of(tmp->w5node.next, w5_node_t, w5node);
	}

	if (!byte_start)
	{
		TE("a fatal error occurred; byte_start: %p;", byte_start);
		abort();
	}

	tmp = byte_start;
	tmp_index = byte_start_index;
	for (tmp_index = byte_start_index; tmp_index <= display_win5_context_lines; tmp_index++)
	{
		wmove(display_resource.wins[5], tmp_index, 1);
		wprintw(display_resource.wins[5], "%*s", display_win5_context_cols, "");
		mvwprintw(display_resource.wins[5], tmp_index, 1, "%s", tmp->content);

		if (l1l2node->byte_end > tmp->endindex) 
		{
			if (!(tmp->w5node.next))
			{
				TE("a fatal error occurred; l1l2node: %p; l1l2node->byte_start: %d;", l1l2node, l1l2node->byte_start);
				abort();
			}
			tmp = container_of(tmp->w5node.next, w5_node_t, w5node);
			continue;
		}
		break;
	}

	wrefresh(display_resource.wins[5]);

	RVoid();
}


/**
 * @brief
 * win4 fills the color of the specified area of ​​win5
 * @param l1l2node win4 specified node
 */
void display_win4_fills_win5_specified_area_color(l1l2_node_t * l1l2node)
{
	TC("Called { %s(%p)", __func__, l1l2node);

	if (!l1l2node) {
		TE("param error; l1l2node: %p", l1l2node);
		abort();
	}

	if (l1l2node->byte_start > INFONODE_BYTE_START_MAX || l1l2node->byte_end > INFONODE_BYTE_END_MAX 
		|| l1l2node->byte_start < 0 || l1l2node->byte_end < 0)
	{
		TE("byte_start or byte_end is problems; l1l2node->byte_start: %d; l1l2node->byte_end: %d",
		   l1l2node->byte_start, l1l2node->byte_end);
		abort();
	}

	if (l1l2node->byte_start == 0 && l1l2node->byte_end == 0)
		RVoid();

	if (l1l2node->byte_start < a2d_info.w5_displayed_start_byte_index)
	{
		w5_node_t *tmp_w5_head = a2d_info.w5_displayed_list_head;
		unsigned short tmp_w5_start_byte_index = a2d_info.w5_displayed_start_byte_index;
		while (l1l2node->byte_start < tmp_w5_start_byte_index)
		{
			if (!(tmp_w5_head->w5node.prev))
			{
				TE("a fatal error occurred; l1l2node: %p; l1l2node->byte_start: %d; tmp_w5_start_byte_index: %hu",
				   l1l2node, l1l2node->byte_start, tmp_w5_start_byte_index);
				abort();
			}

			tmp_w5_head = container_of(tmp_w5_head->w5node.prev, w5_node_t, w5node);
			tmp_w5_start_byte_index = tmp_w5_head->startindex;
		}

		display_win_5_redraw_interface(tmp_w5_head, tmp_w5_head, 1);
	}

	DISPLAY_WIN4_CLEAR_WIN5_CURLINE_COLOR();

	w5_node_t * byte_start = NULL, * byte_tail = NULL, * tmp = NULL;
	unsigned short byte_start_index = 0, byte_tail_index = 0, tmp_index = 1;

	for (tmp_index = 1, tmp = a2d_info.w5_displayed_list_head; tmp_index <= display_win5_context_lines; tmp_index++)
	{
		if (l1l2node->byte_start >= tmp->startindex && l1l2node->byte_start <= tmp->endindex)
		{
			byte_start = tmp;
			byte_start_index = tmp_index;
		}
		if (l1l2node->byte_end >= tmp->startindex && l1l2node->byte_end <= tmp->endindex) 
		{
			byte_tail = tmp;
			byte_tail_index = tmp_index;
			break;
		}

		if (!(tmp->w5node.next))
		{
			TE("a fatal error occurred; l1l2node: %p; l1l2node->byte_start: %d;", l1l2node, l1l2node->byte_start);
			abort();
		}
		tmp = container_of(tmp->w5node.next, w5_node_t, w5node);
	}

	unsigned char hex_start = 0, hex_tail = 0, char_start = 0, char_tail = 0;

	if (!byte_start)
	{
		TE("a fatal error occurred; byte_start: %p;", byte_start);
		abort();
	}

	if (byte_start == byte_tail)
	{
		if (byte_start_index != byte_tail_index)
		{
			TE("a fatal error occurred; byte_start(%p) == byte_tail(%p); but byte_start_index(%hu) != byte_tail_index(%hu)",
			   byte_start, byte_tail, byte_start_index, byte_tail_index);
			abort();
		}
		if ((l1l2node->byte_end - l1l2node->byte_start) > 15)
		{
			TE("a fatal error occurred; byte_start(%p) == byte_tail(%p); but (l1l2node->byte_end(%hu) - l1l2node->byte_start(%hu)) > 15",
			   byte_start, byte_tail, l1l2node->byte_end, l1l2node->byte_start);
			abort();
		}
	}

	if (byte_start_index == byte_tail_index)
	{
		if (byte_start != byte_tail)
		{
			TE("a fatal error occurred; byte_start_index(%hu) == byte_tail_index(%hu); but byte_start(%p) != byte_tail(%p)",
			   byte_start_index, byte_tail_index, byte_start, byte_tail);
			abort();
		}
		if ((l1l2node->byte_end - l1l2node->byte_start) > 15)
		{
			TE("a fatal error occurred; byte_start_index(%hu) == byte_tail_index(%hu); but (l1l2node->byte_end(%hu) - l1l2node->byte_start(%hu)) > 15",
			   byte_start_index, byte_tail_index, l1l2node->byte_end, l1l2node->byte_start);
			abort();
		}
	}

	if (byte_start == byte_tail && byte_start_index == byte_tail_index && (l1l2node->byte_end - l1l2node->byte_start) <= 15)
	{
		hex_start = clhco[l1l2node->byte_start % CLHCO_NUMBER].hex_offset_start;
		hex_tail = clhco[l1l2node->byte_end % CLHCO_NUMBER].hex_offset_tail;
		char_start = clhco[l1l2node->byte_start % CLHCO_NUMBER].char_offset;
		char_tail = clhco[l1l2node->byte_end % CLHCO_NUMBER].char_offset;
		wattron(display_resource.wins[5], COLOR_PAIR(5));
		mvwaddnstr(display_resource.wins[5], byte_start_index, hex_start, byte_start->content + hex_start - 1, hex_tail - hex_start + 1);
		mvwaddnstr(display_resource.wins[5], byte_start_index, char_start, byte_start->content + char_start - 1, char_tail - char_start + 1);
		wattroff(display_resource.wins[5], COLOR_PAIR(5));
		wrefresh(display_resource.wins[5]);
		RVoid();
	}

	if (!(byte_start->w5node.next))
	{
		TE("a fatal error occurred; byte_start: %p; byte_start->w5node.next: %p;", byte_start, byte_start->w5node.next);
		abort();
	}

	hex_start = clhco[l1l2node->byte_start % CLHCO_NUMBER].hex_offset_start;
	hex_tail = clhco[byte_start->endindex % CLHCO_NUMBER].hex_offset_tail;
	char_start = clhco[l1l2node->byte_start % CLHCO_NUMBER].char_offset;
	char_tail = clhco[byte_start->endindex % CLHCO_NUMBER].char_offset;
	wattron(display_resource.wins[5], COLOR_PAIR(5));
	mvwaddnstr(display_resource.wins[5], byte_start_index, hex_start, byte_start->content + hex_start - 1, hex_tail - hex_start + 1);
	mvwaddnstr(display_resource.wins[5], byte_start_index, char_start, byte_start->content + char_start - 1, char_tail - char_start + 1);
	wattroff(display_resource.wins[5], COLOR_PAIR(5));

	tmp = container_of(byte_start->w5node.next, w5_node_t, w5node);
	for (tmp_index = (byte_start_index + 1); tmp_index <= display_win5_context_lines; tmp_index++)
	{
		if (byte_tail == tmp) 
		{
			hex_start = clhco[tmp->startindex % CLHCO_NUMBER].hex_offset_start;
			hex_tail = clhco[l1l2node->byte_end % CLHCO_NUMBER].hex_offset_tail;
			char_start = clhco[tmp->startindex % CLHCO_NUMBER].char_offset;
			char_tail = clhco[l1l2node->byte_end % CLHCO_NUMBER].char_offset;
			wattron(display_resource.wins[5], COLOR_PAIR(5));
			mvwaddnstr(display_resource.wins[5], tmp_index, hex_start, tmp->content + hex_start - 1, hex_tail - hex_start + 1);
			mvwaddnstr(display_resource.wins[5], tmp_index, char_start, tmp->content + char_start - 1, char_tail - char_start + 1);
			wattroff(display_resource.wins[5], COLOR_PAIR(5));
			break;
		}

		hex_start = clhco[tmp->startindex % CLHCO_NUMBER].hex_offset_start;
		hex_tail = clhco[tmp->endindex % CLHCO_NUMBER].hex_offset_tail;
		char_start = clhco[tmp->startindex % CLHCO_NUMBER].char_offset;
		char_tail = clhco[tmp->endindex % CLHCO_NUMBER].char_offset;
		wattron(display_resource.wins[5], COLOR_PAIR(5));
		mvwaddnstr(display_resource.wins[5], tmp_index, hex_start, tmp->content + hex_start - 1, hex_tail - hex_start + 1);
		mvwaddnstr(display_resource.wins[5], tmp_index, char_start, tmp->content + char_start - 1, char_tail - char_start + 1);
		wattroff(display_resource.wins[5], COLOR_PAIR(5));

		tmp = container_of(tmp->w5node.next, w5_node_t, w5node);
	}

	wrefresh(display_resource.wins[5]);

	RVoid();
}


/**
 * @brief
 * 	redraw the window 4 interface
 * @param newhead 
 * @param cur
 * @param line
 */
void display_win_4_redraw_interface(l1l2_node_t * newhead, l1l2_node_t * cur, int line)
{
	TC("Called { %s(%p)", __func__, newhead);

	if (!newhead)
	{
		TE("param error; newhead: %p", newhead);
		RVoid();
	}

	int i = 0;
	l1l2_node_t * su = NULL;

	DISPLAY_WIN_4_CONTENT_CLEAR();

	if (newhead->level == 2)
	{
		su = newhead->superior;
		if (su->isexpand == 0)
			newhead = su;
	}

	a2d_info.w4_l1l2_node_list_head = newhead;
	a2d_info.w4_l1l2_node_cur_node = cur;
	a2d_info.w4_l1l2_node_cur_line = line;

	unsigned short rows_num = 1;
	l1l2_node_t *tmp = a2d_info.w4_l1l2_node_list_head;

	for (i = 0; i < display_win4_context_lines; i++)
	{
		if (!tmp)
			break;

		a2d_info.w4_l1l2_node_list_tail = tmp;

		if (rows_num == a2d_info.w4_l1l2_node_cur_line) 
			wattron(display_resource.wins[4], COLOR_PAIR(5));
		else
			wattroff(display_resource.wins[4], COLOR_PAIR(5));

		if (tmp->level == 1)
		{
			if (tmp->isexpand == 1)
			{
				DISPLAY_WIN_DISPLAY_CONTENT_WITH_SPECIFYING_CHAR(
					display_resource.wins[4], rows_num, 2, display_win4_context_cols, '-', "%s", tmp->content);
				tmp = container_of((tmp->l1l2node.next), l1l2_node_t, l1l2node);
				if (!tmp)
				{
					TE("fatal logic error;");
					abort();
				}
				continue;
			}
			else if (tmp->isexpand == 0)
			{
				DISPLAY_WIN_DISPLAY_CONTENT_WITH_SPECIFYING_CHAR(
					display_resource.wins[4], rows_num, 2, display_win4_context_cols, '+', "%s", tmp->content);
				
				if (tmp->l1node.next == NULL) 
				{
					TI("win4 output complete");
					break;
				}
					
				tmp = container_of((tmp->l1node.next), l1l2_node_t, l1node);
				continue;
			}
			else
			{
				TE("fatal logic error; tmp: %p; tmp->level: %d; tmp->isexpand: %d", tmp, tmp->level, tmp->isexpand);
				abort();
			}
		}

		if (tmp->level == 2)
		{
			DISPLAY_WIN_DISPLAY_CONTENT(
				display_resource.wins[4], rows_num, 2, display_win4_context_cols, "%s", tmp->content);

			if (tmp->l1l2node.next == NULL)
			{
				TI("win4 output complete");
				break;
			} 
			
			tmp = container_of((tmp->l1l2node.next), l1l2_node_t, l1l2node);
		}	
	}

	wrefresh(display_resource.wins[4]);

	RVoid();
}


/**
 * @brief
 * 	window 4 move selection up
 */
void display_win_4_move_up_selected_content (void)
{
	TC("Called { %s(void)", __func__);

	if (!a2d_info.w4_l1l2_node_cur_node)
		RVoid();

	if ((a2d_info.w4_l1l2_node_cur_line < 1) || (a2d_info.w4_l1l2_node_cur_line > display_win4_context_lines))
	{
		TE("fatal logic error; a2d_info.w4_l1l2_node_cur_line: %hu", a2d_info.w4_l1l2_node_cur_line);
		abort();
	}

	l1l2_node_t * prev = NULL, * su = NULL;

	if (a2d_info.w4_l1l2_node_cur_node->l1l2node.prev == NULL && a2d_info.w4_l1l2_node_cur_line != 1) {
		TW("warning a2d_info.w4_l1l2_node_cur_line: %d; a2d_info.w4_l1l2_node_cur_node->l1l2node.prev: %p",
		   a2d_info.w4_l1l2_node_cur_line, a2d_info.w4_l1l2_node_cur_node->l1l2node.prev);
		RVoid();
	}

	if (a2d_info.w4_l1l2_node_cur_node->l1l2node.prev == NULL /*&& a2d_info.w4_l1l2_node_cur_line == 1*/)
	{
		display_popup_message_notification("It's already at the top");
		RVoid();
	}

	prev = container_of((a2d_info.w4_l1l2_node_cur_node->l1l2node.prev), l1l2_node_t, l1l2node);
	if (!prev) {
		TE("fatal logic error; prev: %p;", prev);
		abort();
	}

	if ((prev) && a2d_info.w4_l1l2_node_cur_line == 1)
	{
		display_win4_clear_win5_specified_area_color(a2d_info.w4_l1l2_node_cur_node);
		display_win_4_redraw_interface(prev, prev, a2d_info.w4_l1l2_node_cur_line);
		display_win4_fills_win5_specified_area_color(prev);
		RVoid();
	}

	if (a2d_info.w4_l1l2_node_cur_node->level == 1)
	{
		char c = a2d_info.w4_l1l2_node_cur_node->isexpand ? '-' : '+';
		unsigned short rows_num = a2d_info.w4_l1l2_node_cur_line;
		DISPLAY_WIN_DISPLAY_CONTENT_WITH_SPECIFYING_CHAR(
			display_resource.wins[4], rows_num, 2, display_win4_context_cols, c, "%s", a2d_info.w4_l1l2_node_cur_node->content);
	}
	else if (a2d_info.w4_l1l2_node_cur_node->level == 2)
	{
		unsigned short rows_num = a2d_info.w4_l1l2_node_cur_line;
		DISPLAY_WIN_DISPLAY_CONTENT(
			display_resource.wins[4], rows_num, 2, display_win4_context_cols, "%s", a2d_info.w4_l1l2_node_cur_node->content);
	}
	else
	{
		TE("fatal logic error; a2d_info.w4_l1l2_node_cur_node: %p; a2d_info.w4_l1l2_node_cur_node->level: %d", 
				a2d_info.w4_l1l2_node_cur_node, a2d_info.w4_l1l2_node_cur_node->level);
		abort();
	}

	display_win4_clear_win5_specified_area_color(a2d_info.w4_l1l2_node_cur_node);

	if (prev->level == 2) 
	{
		su = prev->superior;
		if (su->isexpand == 0)
			prev = su;
	}

	wattron(display_resource.wins[4], COLOR_PAIR(5));

	if (prev->level == 1) 
	{
		char c = prev->isexpand ? '-' : '+';
		unsigned short rows_num = a2d_info.w4_l1l2_node_cur_line - 1;
		DISPLAY_WIN_DISPLAY_CONTENT_WITH_SPECIFYING_CHAR(
			display_resource.wins[4], rows_num, 2, display_win4_context_cols, c, "%s", prev->content);
	}
	else if (prev->level == 2)
	{
		unsigned short rows_num = a2d_info.w4_l1l2_node_cur_line - 1;
		DISPLAY_WIN_DISPLAY_CONTENT(
			display_resource.wins[4], rows_num, 2, display_win4_context_cols, "%s", prev->content);
	}
	else 
	{
		TE("fatal logic error; prev: %p; prev->level: %d", prev, prev->level);
		abort();
	}

	wattroff(display_resource.wins[4], COLOR_PAIR(5));

	display_win4_fills_win5_specified_area_color(prev);

	a2d_info.w4_l1l2_node_cur_line--;
	a2d_info.w4_l1l2_node_cur_node = prev;

	wrefresh(display_resource.wins[4]);

	RVoid();
}


/**
 * @brief
 * 	redraw the window 5 interface
 */
void display_win_5_redraw_interface(w5_node_t * newhead, w5_node_t * cur, int line)
{
	TC("Called { %s(%p, %p, %d)", __func__, newhead, cur, line);

	int i = 0;
	w5_node_t * w5tmp = NULL;
	unsigned short rows_num = 1;

	a2d_info.w5_displayed_cur_line_number = line;
	a2d_info.w5_displayed_list_head = w5tmp = newhead;
	a2d_info.w5_displayed_cur_node = cur;
	a2d_info.w5_displayed_start_byte_index = w5tmp->startindex;

	for (i = 0; i < display_win5_context_lines; i++)
	{
		if (!w5tmp) break;

		a2d_info.w5_displayed_list_tail = w5tmp;

		if (w5tmp == a2d_info.w5_displayed_cur_node)
			wattron(display_resource.wins[5], COLOR_PAIR(5));
		else
			wattroff(display_resource.wins[5], COLOR_PAIR(5));

		mvwprintw(display_resource.wins[5], (rows_num + i), 1, "%s", w5tmp->content);

		if (!(w5tmp->w5node.next)) {
			TI("win5 output complete");
			break;
		}

		w5tmp = container_of((w5tmp->w5node.next), w5_node_t, w5node);
	}

	a2d_info.w5_displayed_end_byte_index = a2d_info.w5_displayed_list_tail->endindex;

	wrefresh(display_resource.wins[5]);

	RVoid();
}


/**
 * @brief
 * 	window 5 move selection up
 */
void display_win_5_move_up_selected_content(void)
{
	TC("Called { %s(void)", __func__);

	if (!a2d_info.w5_displayed_cur_node)
		RVoid();

	if (a2d_info.w5_displayed_cur_line_number < 1 || a2d_info.w5_displayed_cur_line_number > display_win5_context_lines) {
		TW("warning a2d_info.w5_displayed_cur_line_number value is error");
		RVoid();
	}

	if (a2d_info.w5_displayed_cur_node->w5node.prev == NULL && a2d_info.w5_displayed_cur_line_number != 1) {
		TW("warning a2d_info.w5_displayed_cur_line_number: %d; a2d_info.w5_displayed_cur_node->w5node.prev: %p", 
				a2d_info.w5_displayed_cur_line_number, a2d_info.w5_displayed_cur_node->w5node.prev);
		RVoid();
	}

	if (a2d_info.w5_displayed_cur_node->w5node.prev == NULL) {
		display_popup_message_notification("It's already at the top");
		RVoid();
	}

	w5_node_t * prev = container_of(a2d_info.w5_displayed_cur_node->w5node.prev, w5_node_t, w5node);
	if (!prev) {
		TE("fatal logic error; prev: %p;", prev);
		abort();
	} 

	if ((a2d_info.w5_displayed_cur_node == a2d_info.w5_displayed_list_head) && (a2d_info.w5_displayed_cur_line_number == 1) && (prev)) {
		display_win_5_redraw_interface(prev, prev, a2d_info.w5_displayed_cur_line_number);
		RVoid();
	}

	wmove(display_resource.wins[5], a2d_info.w5_displayed_cur_line_number, 1);
	wprintw(display_resource.wins[5], "%*s", display_win5_context_cols, "");
	mvwprintw(display_resource.wins[5], a2d_info.w5_displayed_cur_line_number, 1, "%s", a2d_info.w5_displayed_cur_node->content);

	a2d_info.w5_displayed_cur_line_number--;
	a2d_info.w5_displayed_cur_node = prev;

	wattron(display_resource.wins[5], COLOR_PAIR(5));
	wmove(display_resource.wins[5], a2d_info.w5_displayed_cur_line_number, 1);
	wprintw(display_resource.wins[5], "%*s", display_win5_context_cols, "");
	mvwprintw(display_resource.wins[5], a2d_info.w5_displayed_cur_line_number, 1, "%s", prev->content);
	wattroff(display_resource.wins[5], COLOR_PAIR(5));

	wrefresh(display_resource.wins[5]);

	RVoid();
}


/**
 * @brief
 * 	Move selection up
 * @memberof winnumber
 * 	window number
 */
void display_move_up_selected_content (int winnumber) 
{
	TC("Called {%s (%d)", __func__, winnumber);

	switch (winnumber)
	{
		case 3:
			display_win_3_move_up_selected_content();
			break;
		case 4:
			display_win_4_move_up_selected_content();
			break;
		case 5:
			display_win_5_move_up_selected_content();
			break;
		default:
			TE("a fatal error occurred");
			abort();
			break;
	}

	RVoid();
}


/**
 * @brief
 * 	window 3 move selection down
 */
void display_win_3_move_down_selected_content(void)
{
	//TC("Called { %s(void)", __func__);

	TI("a2d_info.w3_displayed_cur_node: %p", a2d_info.w3_displayed_cur_node);
	TI("a2d_info.w3_displayed_cur_index: %hu", a2d_info.w3_displayed_cur_index);

	if (!a2d_info.w3_displayed_cur_node)
		return ;
	
	a2d_info.is_manual_flag = A2D_MANUAL;

	nd_dll_t *node = a2d_info.w3_displayed_cur_node;
	infonode_t *infonode = container_of(node, infonode_t, listnode);
	unsigned long tmp = __sync_fetch_and_add(&(d2c_statistical_count.packages), 0);

	TI("infonode->g_store_index: %lu; tmp: %lu", infonode->g_store_index, tmp);

	if (infonode->g_store_index == (tmp - 1))
	{
		display_popup_message_notification("It's already at the bottom");
		//RVoid();
		return ;
	}

	if (node->next == NULL)
	{
		a2d_info.is_manual_flag = A2D_MANUAL_BOTTOM;
		nd_delay_microsecond(0, 1000000);
		//RVoid();
		return ;
	}

	a2d_info.w3_displayed_cur_node = node->next;
	a2d_info.w3_displayed_cur_index++;

	//RVoid();
	return ;
}


/**
 * @brief
 * 	window 4 move selection down
 */
void display_win_4_move_down_selected_content(void)
{
	TC("Called { %s(void)", __func__);

	if (!a2d_info.w4_l1l2_node_cur_node)
		RVoid();

	if ((a2d_info.w4_l1l2_node_cur_line < 1) || (a2d_info.w4_l1l2_node_cur_line > display_win4_context_lines))
	{
		TE("fatal logic error; a2d_info.w4_l1l2_node_cur_line: %hu", a2d_info.w4_l1l2_node_cur_line);
		abort();
	}

	l1l2_node_t *next = NULL, *nextsu = NULL, *newhead = NULL, *tmp = NULL;

	if (a2d_info.w4_l1l2_node_cur_node->l1l2node.next == NULL)
	{
		display_popup_message_notification("It's already at the bottom");
		RVoid();
	}

	next = container_of((a2d_info.w4_l1l2_node_cur_node->l1l2node.next), l1l2_node_t, l1l2node);

	if (a2d_info.w4_l1l2_node_cur_node->level == 1 && a2d_info.w4_l1l2_node_cur_node->l1node.next != NULL)
		nextsu = container_of((a2d_info.w4_l1l2_node_cur_node->l1node.next), l1l2_node_t, l1node);

	if ((next) && a2d_info.w4_l1l2_node_cur_node == a2d_info.w4_l1l2_node_list_tail &&
		a2d_info.w4_l1l2_node_cur_node->level == 1 && a2d_info.w4_l1l2_node_cur_node->isexpand == 0 &&
		!nextsu)
	{
		display_popup_message_notification("It's already at the bottom");
		RVoid();
	}

	if ((next) && (a2d_info.w4_l1l2_node_cur_line == display_win4_context_lines))
	{
		tmp = container_of((a2d_info.w4_l1l2_node_list_head->l1l2node.next), l1l2_node_t, l1l2node);

		if (tmp->level == 2) 
		{
			if (!(tmp->superior->isexpand))
				newhead = container_of((tmp->superior->l1node.next), l1l2_node_t, l1node);
			else
				newhead = tmp;
		}
		if (tmp->level == 1)
			newhead = tmp;
		display_win4_clear_win5_specified_area_color(a2d_info.w4_l1l2_node_cur_node);
		display_win_4_redraw_interface(newhead, next, a2d_info.w4_l1l2_node_cur_line);
		display_win4_fills_win5_specified_area_color(a2d_info.w4_l1l2_node_cur_node);
		RVoid();
	}

	if (a2d_info.w4_l1l2_node_cur_node->level == 1)
	{
		char c = a2d_info.w4_l1l2_node_cur_node->isexpand ? '-' : '+';
		unsigned short rows_num = a2d_info.w4_l1l2_node_cur_line;
		DISPLAY_WIN_DISPLAY_CONTENT_WITH_SPECIFYING_CHAR(
			display_resource.wins[4], rows_num, 2, display_win4_context_cols, c, "%s", a2d_info.w4_l1l2_node_cur_node->content);
	}
	else if (a2d_info.w4_l1l2_node_cur_node->level == 2)
	{
		unsigned short rows_num = a2d_info.w4_l1l2_node_cur_line;
		DISPLAY_WIN_DISPLAY_CONTENT(
			display_resource.wins[4], rows_num, 2, display_win4_context_cols, "%s", a2d_info.w4_l1l2_node_cur_node->content);
	}
	else
	{
		TE("fatal logic error; a2d_info.w4_l1l2_node_cur_node: %p; a2d_info.w4_l1l2_node_cur_node->level: %d",
		   a2d_info.w4_l1l2_node_cur_node, a2d_info.w4_l1l2_node_cur_node->level);
		abort();
	}

	display_win4_clear_win5_specified_area_color(a2d_info.w4_l1l2_node_cur_node);

	if (next->level == 2)
	{
		if (next->superior->isexpand == 0)
			next = container_of((next->superior->l1node.next), l1l2_node_t, l1node);
	}

	wattron(display_resource.wins[4], COLOR_PAIR(5));

	if (next->level == 1) 
	{
		char c = next->isexpand ? '-' : '+';
		unsigned short rows_num = a2d_info.w4_l1l2_node_cur_line + 1;
		DISPLAY_WIN_DISPLAY_CONTENT_WITH_SPECIFYING_CHAR(
			display_resource.wins[4], rows_num, 2, display_win4_context_cols, c, "%s", next->content);
	}
	else if (next->level == 2) 
	{
		unsigned short rows_num = a2d_info.w4_l1l2_node_cur_line + 1;
		DISPLAY_WIN_DISPLAY_CONTENT(
			display_resource.wins[4], rows_num, 2, display_win4_context_cols, "%s", next->content);
	}
	else
	{
		TE("fatal logic error; next: %p; next->level: %d", next, next->level);
		abort();
	}

	wattroff(display_resource.wins[4], COLOR_PAIR(5));

	display_win4_fills_win5_specified_area_color(next);

	a2d_info.w4_l1l2_node_cur_line++;
	a2d_info.w4_l1l2_node_cur_node = next;

	wrefresh(display_resource.wins[4]);

	RVoid();
}


/**
 * @brief
 * 	window 5 move selection down
 */
void display_win_5_move_down_selected_content(void)
{
	TC("Called { %s(void)", __func__);

	if (!a2d_info.w5_displayed_cur_node)
		RVoid();

	if (a2d_info.w5_displayed_cur_line_number < 1 || 
			a2d_info.w5_displayed_cur_line_number > display_win5_context_lines) {
		TW("warning a2d_info.w5_displayed_cur_line_number value is error");
		RVoid();
	}

	if (a2d_info.w5_displayed_cur_node == a2d_info.w5_displayed_list_tail && 
		a2d_info.w5_displayed_cur_node->w5node.next == NULL) {
		display_popup_message_notification("It's already at the bottom");
		RVoid();
	}

	if (a2d_info.w5_displayed_cur_node->w5node.next == NULL && 
		a2d_info.w5_displayed_cur_node != a2d_info.w5_displayed_list_tail) {
		TW("warning value is error; a2d_info.w5_displayed_cur_node->w5node.next: %p; a2d_info.w5_displayed_cur_node:%p; a2d_info.w5_displayed_list_tail: %p",
		   a2d_info.w5_displayed_cur_node->w5node.next, a2d_info.w5_displayed_cur_node, a2d_info.w5_displayed_list_tail);
		RVoid();
	}

	if (!(a2d_info.w5_displayed_cur_node->w5node.next)) {
		display_popup_message_notification("It's already at the bottom");
		RVoid();
	}

	w5_node_t * next = container_of((a2d_info.w5_displayed_cur_node->w5node.next), w5_node_t, w5node);

	if (a2d_info.w5_displayed_cur_node == a2d_info.w5_displayed_list_tail && 
		a2d_info.w5_displayed_cur_node->w5node.next &&
		a2d_info.w5_displayed_cur_line_number == display_win5_context_lines)
	{
		w5_node_t * newhead = container_of(a2d_info.w5_displayed_list_head->w5node.next, w5_node_t, w5node);
		display_win_5_redraw_interface(newhead, next, a2d_info.w5_displayed_cur_line_number);
		RVoid();
	}

	wmove(display_resource.wins[5], a2d_info.w5_displayed_cur_line_number, 1);
	wprintw(display_resource.wins[5], "%*s", display_win5_context_cols, "");
	mvwprintw(display_resource.wins[5], a2d_info.w5_displayed_cur_line_number, 1, "%s", a2d_info.w5_displayed_cur_node->content);

	a2d_info.w5_displayed_cur_line_number++;
	a2d_info.w5_displayed_cur_node = next;

	wattron(display_resource.wins[5], COLOR_PAIR(5));
	wmove(display_resource.wins[5], a2d_info.w5_displayed_cur_line_number, 1);
	wprintw(display_resource.wins[5], "%*s", display_win5_context_cols, "");
	mvwprintw(display_resource.wins[5], a2d_info.w5_displayed_cur_line_number, 1, "%s", next->content);
	wattroff(display_resource.wins[5], COLOR_PAIR(5));

	wrefresh(display_resource.wins[5]);

	RVoid();
}


/**
 * @brief
 * 	Move selection down
 * @param winnumber
 * 	window number
 */
void display_move_down_selected_content (int winnumber)
{
	TC("Called {%s (%d)", __func__, winnumber);

	switch (winnumber)
	{
		case 3:
			display_win_3_move_down_selected_content();
			break;
		case 4:
			display_win_4_move_down_selected_content();
			break;
		case 5:
			display_win_5_move_down_selected_content();
			break;
		default:
			TE("a fatal error occurred");
			abort();
			break;
	}

	RVoid();
}


/**
 * @brief
 * 	execute the enter key behavior
 * @param winnumber
 * 	window number
 */
void display_exec_enter_behavior(int winnumber)
{
	TC("Called {%s (%d)", __func__, winnumber);

	if (winnumber != 4)
		RVoid();

	if (!a2d_info.w4_l1l2_node_cur_node)
		RVoid();

	if (a2d_info.w4_l1l2_node_cur_node->level != 1)
		RVoid();

	if (a2d_info.w4_l1l2_node_cur_node->isexpand == 0)
		a2d_info.w4_l1l2_node_cur_node->isexpand = 1;
	else if (a2d_info.w4_l1l2_node_cur_node->isexpand == 1)
		a2d_info.w4_l1l2_node_cur_node->isexpand = 0;
	else
	{
		TE("a fatal error occurred; a2d_info.w4_l1l2_node_cur_node: %p; a2d_info.w4_l1l2_node_cur_node->level: %d",
		   a2d_info.w4_l1l2_node_cur_node, a2d_info.w4_l1l2_node_cur_node->level);
		abort();
	}

	display_win_4_redraw_interface(a2d_info.w4_l1l2_node_list_head, 
		a2d_info.w4_l1l2_node_cur_node, a2d_info.w4_l1l2_node_cur_line);

	RVoid();
}


/**
 * @brief
 * 	Pop-up message notification
 * @memberof msg
 * 	Notification message content
 */
void display_popup_message_notification(const char * msg)
{
	TC("Called { %s(%s)", __func__, msg);

	int rows, cols;
	getmaxyx(stdscr, rows, cols);

	int msg_len = strlen(msg);
	int win_height = 3;
	int win_width = msg_len + 4;

	WINDOW *popup = newwin(win_height, win_width, (rows - win_height) / 2, (cols - win_width) / 2);
	box(popup, 0, 0); 

	mvwprintw(popup, 1, 2, "%s", msg);

	wbkgd(popup, COLOR_PAIR(4));

	wrefresh(popup);
	usleep(500000);

	wclear(popup);
	werase(popup);
	wrefresh(popup);
	delwin(popup);

	display_draw_brief_information_box();
	display_draw_more_information_box();
	display_draw_raw_information_box();

	refresh();

	RVoid();
}