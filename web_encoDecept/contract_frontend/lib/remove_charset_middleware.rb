# lib/remove_charset_middleware.rb
class RemoveCharsetMiddleware
    def initialize(app)
      @app = app
    end
  
    def call(env)
      status, headers, response = @app.call(env)
      headers["Content-Type"] = headers["Content-Type"].sub(/; charset=.*$/, '') if headers["Content-Type"]
      [status, headers, response]
    end
  end
  