#include "GPUCipherDevice.hpp"
#include "../logging.hpp"
#include <math.h> 

template < typename S, typename F >
    paracrypt::GPUCipherDevice < S, F >::~GPUCipherDevice()
{
    boost::unique_lock< boost::shared_mutex > lock(this->streams_access);
	typename boost::unordered_map<int,S>::iterator iter;
    for(iter = this->streams.begin(); iter != this->streams.end(); ++iter)
    {
//    	  LOG_TRACE(boost::format("~GPUCipherDevice(): delStream(%d)") % iter->first);
          delStream(iter->first);
    }
}

template < typename S, typename F >
    int paracrypt::GPUCipherDevice < S, F >::getGridSize(int n_blocks,
							 int
							 threadsPerCipherBlock)
{
    float fGridSize =
	n_blocks * threadsPerCipherBlock /
	(float) this->getThreadsPerThreadBlock();
    int gridSize = ceil(fGridSize);
    return gridSize;
}

template < typename S, typename F >
    int paracrypt::GPUCipherDevice < S, F >::addStream()
{
    boost::unique_lock< boost::shared_mutex > lock(this->streams_access);
    int id = this->streams.size();
    this->streams[id] = newStream();
//    LOG_TRACE(boost::format("GPUCipherDevice.addStream() => %d") % id);
    return id;
}

template < typename S, typename F >
    void paracrypt::GPUCipherDevice < S, F >::delStream(int stream_id)
{
    boost::unique_lock< boost::shared_mutex > lock(this->streams_access);
    freeStream(this->streams[stream_id]);
    this->streams.erase(stream_id);
}

template < typename S, typename F >
    S paracrypt::GPUCipherDevice < S, F >::acessStream(int stream_id)
{
    boost::shared_lock < boost::shared_mutex > lock(this->streams_access);
    return this->streams[stream_id];
}