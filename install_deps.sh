pip3 install -r requirements.txt

docker run -v $(pwd)/vendor:/outputs -it lambci/lambda:build-python3.6 pip install lxml defusedxml cffi signxml pyOpenSSL -t /outputs/
