#!/bin/bash
source ENV/bin/activate
python app.py >console.log 2>&1 &
