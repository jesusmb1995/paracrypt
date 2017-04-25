/*
 *  Copyright (C) 2017 Jesus Martin Berlanga. All Rights Reserved.
 *
 *  This file is part of Paracrypt.
 *
 *  Paracrypt is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Foobar is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "Timer.hpp"

void Timer::tic() {
	this->begin = clock();
}

double Timer::toc() {
	clock_t end = clock();
	double elapsed_clocks = double(end-begin);
	// double seconds = elapsed_clocks / CLOCKS_PER_SEC;
	return elapsed_clocks;
}

double Timer::toc_seconds() {
	return this->toc()/CLOCKS_PER_SEC;
}
