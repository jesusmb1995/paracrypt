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

def twoDecimals(vals):
	upd=[]
	for i in range(len(vals)):
		updated = round(vals[i],2);
		upd.append(updated);
	return upd;

import matplotlib.pyplot as plt
def plotPerformance(title,path,files,outputTag="",zoomFrom=0):
	plt.figure(figsize=(20,5))
	ticks_set = False
	for fileName in files:
		filePath = path + fileName
		[sizes,times] = load_raw_data(filePath)

		# only plot results for files greater than zoom
		size_idx = 0
		assert(len(sizes) == len(times))
		while size_idx < len(sizes):
			if sizes[size_idx] < zoomFrom:
				del sizes[size_idx]
				del times[size_idx]
			else:
				size_idx += 1;
			
		mbs = getMB(sizes)
		ss = getSecs(times)
		speeds = calcSpeed(mbs,ss)	
		formats = formatBytes(sizes)
		cipherName = fileName.split("_performance.txt")[0]
		if not ticks_set:
			plt.xscale('log')
			plt.xticks(sizes, formats)
		plt.plot(sizes,speeds,'-s', label=cipherName)
	plt.ylabel('MB/s')
	if zoomFrom == 0:
		plt.legend(loc=2) # place top-left
	# else don't plot legend
	plt.gca().yaxis.grid(True)
	plt.title(title)
	plt.savefig(path+title+outputTag+"_plot.png", bbox_inches='tight')
	#plt.show()
	plt.close()

#              size1 size2 size3 ...
# result_title MB/s  MB/s  MB/s  ...
# result_tilte MB/s  MB/s  MB/s  ...
# ...
#
import numpy
def genTables(title,path,files,outputTag="",genFrom=0):
	table=[]
	sizes_set = False
	for fileName in files:
		filePath = path + fileName
		[sizes,times] = load_raw_data(filePath)

		# only plot results for files greater than genFrom
		size_idx = 0
		assert(len(sizes) == len(times))
		while size_idx < len(sizes):
			if sizes[size_idx] < genFrom:
				del sizes[size_idx]
				del times[size_idx]
			else:
				size_idx += 1;

		mbs = getMB(sizes)
		ss = getSecs(times)
		speeds = twoDecimals(calcSpeed(mbs,ss))
		formats = formatBytes(sizes)
		cipherName = fileName.split("_performance.txt")[0]
		if not table:
			first_row = ["performance in MB/s | file size"] + formats;
			table.append(first_row);
		row = [cipherName] + speeds;
		table.append(row);
	#print table
	numpy.savetxt(path+title+outputTag+".csv",table, delimiter=";", fmt="%s")

# plot graph, zoomed graph, and tables
def plotSuite(title,path,files,zoomFrom):
	plotPerformance(title,path,files);
	plotPerformance(title,path,files,"_zoom",zoomFrom);
	genTables(title,path,files);
