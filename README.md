# google-bash

This repository provides a basic implementation of Google OAuth and some
Google API calls.

It is written almost exclusively in bash (inline Python2 for json parsing
doesn't count, does it?!).

## Installation

Download from <https://github.com/rmk2/google-bash>.

## Usage

### oauth.sh

If you put the file somewhere on your `$PATH`, run:

	$ oauth.sh +-f ARG [+-l ARG] [+-d ARG] [--] ARGS...
	
Otherwise, prepend the path to where the script is located.

## License

Copyright © 2019 rmk2

This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
