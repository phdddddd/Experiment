ib_write_bw 10.12.188.8 -a >write_bw_without_analyze.txt
sleep(15)
ib_write_lat 10.12.188.8 -a >write_lat_without_analyze.txt
sleep(15)
ib_read_bw -a 10.12.188.8  >read_bw_without_analyze.txt
sleep(15)
ib_read_lat -a  10.12.188.8 >read_lat_without_analyze.txt
sleep(15)


ib_write_bw -a 10.12.188.8  >write_bw_with_analyze.txt
sleep(15)
ib_write_lat -a 10.12.188.8  >write_lat_with_analyze.txt
sleep(15)
ib_read_bw -a 10.12.188.8  >read_bw_with_analyze.txt
sleep(15)
ib_read_lat -a  10.12.188.8 >read_lat_with_analyze.txt
sleep(15)