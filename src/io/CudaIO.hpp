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

//	EMPTY_BUFFER = -1, // For ASYNC implementations: We have to wait until the buffer is filled

class CudaIO: IO {
private:
	typedef struct io_buffer {
		const unsigned char* in;
		const unsigned char* out;
		const unsigned long size;
		unsigned long read_pointer;
	} io_buffer; // TODO
    unsigned char* buffers[];
    unsigned long bufferSizes[];
    // file pos
	int nBuffers;
	bool initialized;
protected:
	unsigned char* getBuffer(int bufferId);
	unsigned long getBufferSize(int bufferId);
	int getNBuffers();
public:
	CudaIO();
	virtual ~CudaIO();

    // permits to read with different
	// buffers with different sizes
	// TODO mejor poner distribución de pesos y tamaño de bloque
	//   para que asigne los maximos posibles
	bool initializeBuffers(unsigned long *bufferSizes, int nBuffers);
	void freeBuffers();

	// return the number of read byes
	//  returns -1 if EOF has been reached
	// TODO remove from the in_buffer
	// TODO add to the out_buffer once readed
	virtual unsigned long read(int bufferId, char* data[]) = 0;
	virtual dump(int bufferId) = 0;
};

} /* namespace paracrypt */

#endif /* INPUTOUTPUT_H_ */
