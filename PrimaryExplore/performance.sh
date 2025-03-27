ib_write_bw 10.12.188.8 -a >write_bw_without_analyze.txt
sleep(15)
ib_write_lat 10.12.188.8 -a >write_lat_without_analyze.txt
sleep(15)
ib_read_bw 10.12.188.8 -a >read_bw_without_analyze.txt
sleep(15)
ib_read_lat 10.12.188.8 -a >read_lat_without_analyze.txt
sleep(15)