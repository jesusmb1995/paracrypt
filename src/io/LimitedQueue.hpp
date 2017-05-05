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

#ifndef LIMITEDQUEUE_HPP_
#define LIMITEDQUEUE_HPP_

#include <queue>

namespace paracrypt {

template <typename T>
class LimitedQueue {
private:
	std::queue<T> *queue;
	const unsigned int limit;
public:
	LimitedQueue(const unsigned int limit);
	~LimitedQueue();
	void enqueue(T v);
	T dequeue();
	const unsigned int getLimit();
	const unsigned int size();
	bool empty();
};

} /* namespace paracrypt */

#include "LimitedQueue.tpp"

#endif /* LIMITEDQUEUE_HPP_ */
