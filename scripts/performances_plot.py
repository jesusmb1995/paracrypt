# return [[sizes],[times]]
def load_raw_data(fileName):
	sizes=[] # in bytes
	times=[] # in nanoseconds
	fp = open(fileName);
	rows = fp.read().split("\n")
	for row in rows:
		if row != "":
			columns = row.split(" ")
			size = int(columns[0])
			time = int(columns[1])
			sizes.append(size)
			times.append(time)
	fp.close()
	return [sizes,times]

one_kb = 1000.0
one_mb = 1000.0*one_kb

def getMB(bytess):
	mbs = [bytes / one_mb for bytes in bytess];
	return mbs

def getKB(bytess):
	kbs = [bytes / one_kb for bytes in bytess];
	return kbs

def getSecs(nss):
	ss = [ns / 1000000000.0 for ns in nss];
	return ss

# return [[values],[units]]
def formatBytes(bytess):
	formats = []
	for bytes in bytess:
		value = 0
		unit = ""
		if bytes >= one_mb:
			unit = "MB"
			value = bytes/one_mb
			value = int(round(value))
		elif bytes >= one_kb:
			unit = "KB"
			value = bytes/one_kb
			value = int(round(value))
		formatted = str(value) + " " + unit;
		formats.append(formatted)
	return formats

# sizeTimes -> [[sizes],[times]]
def calcSpeed(sizes,times):
	speeds=[]
	assert(len(sizes) == len(times))
	for i in range(len(sizes)):
		speed = sizes[i] / times[i]
		speeds.append(speed)
	return speeds


path="../info/"

import matplotlib.pyplot as plt
def plotPerformance(title,filesPath):
	plt.figure(figsize=(20,5))
	ticks_set = False
	for filePath in filesPath:
		[sizes,times] = load_raw_data(filePath)
		mbs = getMB(sizes)
		ss = getSecs(times)
		speeds = calcSpeed(mbs,ss)	
		formats = formatBytes(sizes)
		fileTree = filePath.split("/")
		onlyFileName = fileTree[len(fileTree)-1]
		cipherName = onlyFileName.split("_performance.txt")[0]
		if not ticks_set:
			plt.xscale('log')
			plt.xticks(sizes, formats)
		plt.plot(sizes,speeds,'-s', label=cipherName)
	plt.ylabel('MB/s')
	plt.legend(loc=2) # place top-left
	plt.gca().yaxis.grid(True)
	plt.title(title)
	plt.savefig(path+title+"_plot.png", bbox_inches='tight')
	#plt.show()

# openssl_aes_128_cbc = path+"openssl-aes-128-cbc_performance.txt"
openssl_aes_128_ecb = path+"paracrypt-aes-128-ecb_performance.txt"
paracrypt_aes_128_ecb = path+"openssl-aes-128-ecb_performance.txt"


openssl_aes_128_ctr = path+"paracrypt-aes-128-ctr_performance.txt"
paracrypt_aes_128_ctr = path+"openssl-aes-128-ctr_performance.txt"

#plotPerformance("testing",[openssl_aes_128_cbc])
#plotPerformance("testing",[paracrypt_aes_128_ecb, openssl_aes_128_ecb])
plotPerformance("testing",[paracrypt_aes_128_ctr, openssl_aes_128_ctr])
