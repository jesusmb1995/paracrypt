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
 *  Paracrypt is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Paracrypt.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "LimitedQueue.hpp"
#include "utils/logging.hpp"

namespace paracrypt {

template <typename T>
LimitedQueue<T>::LimitedQueue(unsigned int limit)
: limit(limit)
{
	this->queue = new std::queue<T>;
}

template <typename T>
LimitedQueue<T>::~LimitedQueue() {
	delete this->queue;
}

template <typename T>
const unsigned int paracrypt::LimitedQueue<T>::getLimit() {
	return this->limit;
}

template <typename T>
const unsigned int paracrypt::LimitedQueue<T>::size() {
	return this->queue->size();
}

template <typename T>
bool paracrypt::LimitedQueue<T>::empty() {
	return this->queue->empty();
}

template <typename T>
void paracrypt::LimitedQueue<T>::enqueue(T v) {
	if(this->size() > this->getLimit()) {
		ERR("LimitedQueue is already full.");
	}
	this->queue->push(v);
}

template <typename T>
T paracrypt::LimitedQueue<T>::dequeue() {
	T v = this->queue->front(); 
	this->queue->pop();
	return v;
}

} /* namespace paracrypt */
