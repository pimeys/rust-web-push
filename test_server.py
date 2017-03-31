from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

class TestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        print("HEADERS:")
        print("******************************")
        print(self.headers)
        print("CONTENT:")
        print("******************************")
        print(self.request_data())

        self.send_response(200, "OK")

    def request_data(self):
        content_length = self.headers.getheaders('content-length')
        length         = int(content_length[0]) if content_length else 0

        return self.rfile.read(length)

if __name__ == '__main__':
    server = HTTPServer(('', 8083), TestHandler)
    print("GO")
    server.serve_forever()
