/*
 * Timer.cpp
 *
 *  Created on: Apr 12, 2017
 *      Author:  Jesús Martín Berlanga
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
