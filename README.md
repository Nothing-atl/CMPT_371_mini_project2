in first terminal:

 python prtp.py server --host 127.0.0.1 --port 9000 --outfile recv.txt

 in second terminal:

 python prtp.py client --host 127.0.0.1 --port 9000 --infile to_send.txt
