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

#ifndef INPUTOUTPUT_H_
#define INPUTOUTPUT_H_

namespace paracrypt {

typedef struct io_buffer {
	const int id, chunk_size, size;
	const unsigned char* data;
} io_buffer;

typedef enum {
	EMPTY_BUFFER = -1,
	EOF = -2,
} chunk_read_status;

// bytes_size can be EMPTY_BUFFER or EOF
// If the buffer is empty we have to wait
//  until more data is read and place into
//  the buffer.
typedef struct io_chunk {
   const int io_buffer_id, chunk_index, bytes_size;
   const unsigned char* data;
} io_chunk;

class InputOutput {
private:
	const int rlimitMemLock;
    int lockLimit;
protected:
    int alreadyAllocated;
    virtual void* getPinnedMemory(int bytes);
public:
	InputOutput();
	virtual ~InputOutput();
	void setLockLimit(int bytes);
	int getLockLimit();

    // permits to read with different chunk_sizes
	// return the newly created buffer id
	virtual int createBuffer(int chunk_size, int n_chunks);

	virtual io_chunk readChunkFromBuffer(int io_buffer_id);
};

} /* namespace paracrypt */

#endif /* INPUTOUTPUT_H_ */
