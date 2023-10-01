#! /usr/bin/bash
cd output_2to1_20
sudo docker compose down
cd ..
python3 2to1_20.py -d 100
cd output_2to1_20
sudo docker compose build --no-cache
sudo docker compose up
