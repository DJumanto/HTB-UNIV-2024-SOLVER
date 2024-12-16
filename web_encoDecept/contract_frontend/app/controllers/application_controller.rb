class ApplicationController < ActionController::Base
  # Only allow modern browsers supporting webp images, web push, badges, import maps, CSS nesting, and CSS :has.
  allow_browser versions: :modern
  helper_method :current_user

  before_action :set_default_url_options

  def set_default_url_options
    Rails.application.routes.default_url_options[:host] = request.host
    Rails.application.routes.default_url_options[:port] = request.port
  end

  def current_user
    @current_user ||= fetch_user_data if session[:token]
  end

  private

  def fetch_user_data
    response = HTTP.auth("Token #{session[:token]}").get("http://localhost:8080/api/me/")
    response.status.success? ? response.parse : nil
  end
end
