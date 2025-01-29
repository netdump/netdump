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

/**
 * @brief Define a global variable to store the resources required by TUI
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
 * @brief Format the title bar title
 * @param win: The window that is designated to format the input title
 * @param starty: The starting position of the title bar relative to the window's Y coordinate
 * @param startx: The starting position of the title bar relative to the window's X coordinate
 * @param width: Width of the title bar
 * @param string: Contents of the title bar
 * @param color: Color attribute of the title bar content
 */
int display_format_set_window_title(WINDOW *win, int starty, int startx, int width, char *string, chtype color) {

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

    return 0;
}


/**
 * @brief TUI shows process exit resource destruction
 */
void display_exit_resource_destruction () {

	TC("called { %s", __func__);

	display_exit_TUI_showcase();

	RVoid();
}
