#!/bin/bash
ab -n 100 -c 1 -T "application/json" -p post.json http://localhost:8080/