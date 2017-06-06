import performances_plot_core as p

# show results for files larger than 
#  60 MB at a closer range.
zoom=30*1000*1000

# only generate table results 
#  for files bigger than 4MB
tableFrom=4*1000*1000

# number of streams per gpu
p.plotSuite("streams",
	"../info/",[
		"paracrypt-aes-128-ctr_1-stream_performance.txt",
		"paracrypt-aes-128-ctr_2-stream_performance.txt",
		#"aes-128-ctr_3-stream_performance.txt",
		"paracrypt-aes-128-ctr_4-stream_performance.txt",
		#"aes-128-ctr_5-stream_performance.txt",
		"paracrypt-aes-128-ctr_8-stream_performance.txt",
		#"paracrypt-aes-128-ctr_12-stream_performance.txt",
		"paracrypt-aes-128-ctr_unlimited-streams_performance.txt"
	], zoom)

# CPU-GPU stagging area / IO buffer size
p.plotSuite("staging",
	"../info/",[
		"paracrypt-aes-128-ctr_1MB-staging_performance.txt",
		"paracrypt-aes-128-ctr_2MB-staging_performance.txt",
		#"paracrypt-aes-128-ctr_3MB-staging_performance.txt",
		#"paracrypt-aes-128-ctr_4MB-staging_performance.txt",
		"paracrypt-aes-128-ctr_8MB-staging_performance.txt",
		#"paracrypt-aes-128-ctr_16MB-staging_performance.txt",
		"paracrypt-aes-128-ctr_32MB-staging_performance.txt",
		#"paracrypt-aes-128-ctr_64MB-staging_performance.txt",
		#"paracrypt-aes-128-ctr_128MB-staging_performance.txt",
		"paracrypt-aes-128-ctr_unlimited-staging_performance.txt"
	], zoom)

# parallelism
p.plotSuite("implementations",
	"../info/",[
		"paracrypt-aes-128-ctr-16B_performance.txt",
		"paracrypt-aes-128-ctr-8B_performance.txt",
		"paracrypt-aes-128-ctr-4B_performance.txt",
		"paracrypt-aes-128-ctr-1B_performance.txt"
	], zoom)

# constant vs non-constant GPU memory
p.plotSuite("constants-16B",
	"../info/",[
		"paracrypt-aes-128-ctr-16B_performance.txt",
		"paracrypt-aes-128-ctr_16B-disabled-constant-key_performance.txt",
		"paracrypt-aes-128-ctr_16B-disabled-constant-tables_performance.txt",
		"paracrypt-aes-128-ctr_16B-disabled-constant-gpu-memory_performance.txt",
	], zoom)
p.plotSuite("constants-8B",
	"../info/",[
		"paracrypt-aes-128-ctr-8B_performance.txt",
		"paracrypt-aes-128-ctr_8B-disabled-constant-key_performance.txt",
		"paracrypt-aes-128-ctr_8B-disabled-constant-tables_performance.txt",
		"paracrypt-aes-128-ctr_8B-disabled-constant-gpu-memory_performance.txt",
	], zoom)
p.plotSuite("constants-4B",
	"../info/",[
		"paracrypt-aes-128-ctr-4B_performance.txt",
		"paracrypt-aes-128-ctr_4B-disabled-constant-key_performance.txt",
		"paracrypt-aes-128-ctr_4B-disabled-constant-tables_performance.txt",
		"paracrypt-aes-128-ctr_4B-disabled-constant-gpu-memory_performance.txt",
	], zoom)
p.plotSuite("constants-1B",
	"../info/",[
		"paracrypt-aes-128-ctr-4B_performance.txt",
		"paracrypt-aes-128-ctr_4B-disabled-constant-key_performance.txt",
		"paracrypt-aes-128-ctr_4B-disabled-constant-tables_performance.txt",
		"paracrypt-aes-128-ctr_4B-disabled-constant-gpu-memory_performance.txt",
	], zoom)

# out of order
p.plotSuite("out-of-order",
	"../info/",[
		"paracrypt-aes-128-ctr-16B_performance.txt",
		"paracrypt-aes-128-ctr_out-of-order_performance.txt"
	], zoom)

# parallelism with integer bitwise operators
p.plotSuite("integers-16B",
	"../info/",[
		"paracrypt-aes-128-ctr-16B_performance.txt",
		"paracrypt-aes-128-ctr-16B-integers_performance.txt"
	], zoom)

p.plotSuite("integers-8B",
	"../info/",[
		"paracrypt-aes-128-ctr-8B_performance.txt",
		"paracrypt-aes-128-ctr-8B-integers_performance.txt"
	], zoom)

p.plotSuite("integers-4B",
	"../info/",[
		"paracrypt-aes-128-ctr-4B_performance.txt",
		"paracrypt-aes-128-ctr-4B-integers_performance.txt"
	], zoom)
p.plotSuite("implementations-integers",
	"../info/",[
		"paracrypt-aes-128-ctr-16B-integers_performance.txt",
		"paracrypt-aes-128-ctr-8B-integers_performance.txt",
		"paracrypt-aes-128-ctr-4B-integers_performance.txt",
		"paracrypt-aes-128-ctr-1B_performance.txt"
	], zoom)

# modes of operation (decryption tests)
p.plotSuite("decryption-modes",
	"../info/",[
		"paracrypt-aes-128-ecb_performance.txt",
		"paracrypt-aes-128-ctr_performance.txt",
		"paracrypt-aes-128-cbc_performance.txt",
		"paracrypt-aes-128-cfb_performance.txt"
	], zoom)

# ctr: openssl vs paracrypt
p.plotSuite("OpenSSL-vs-Paracrypt",
	"../info/",[
		"openssl-aes-128-ctr_performance.txt",
		"paracrypt-aes-128-ctr-16B_performance.txt",
	], zoom)

# cbc cfb decrypt: openssl vs paracrypt
p.plotSuite("OpenSSL-vs-Paracrypt-decryption",
	"../info/",[
		"paracrypt-aes-128-cbc_performance.txt",
		"paracrypt-aes-128-cfb_performance.txt",
		"openssl-aes-128-cbc-decryption_performance.txt",
		"openssl-aes-128-cfb-decryption_performance.txt"
	], zoom)

# key size
p.plotSuite("key-size",
	"../info/",[
		"paracrypt-aes-128-ctr-16B_performance.txt",
		"paracrypt-aes-192-ctr-16B_performance.txt",
		"paracrypt-aes-256-ctr-16B_performance.txt",
		"openssl-aes-128-ctr_performance.txt",
		"openssl-aes-192-ctr_performance.txt",
		"openssl-aes-256-ctr_performance.txt"
	], zoom)

