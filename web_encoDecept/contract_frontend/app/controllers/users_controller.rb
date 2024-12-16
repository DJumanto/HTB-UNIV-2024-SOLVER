class UsersController < ApplicationController
  before_action :require_login, only: [:edit, :update]

  def new
  end

  def create
    response = HTTP.post("http://localhost:8080/api/register/", json: { username: params[:username], password: params[:password] })
    if response.status.success?
      redirect_to login_path, notice: 'User created successfully. Please log in.'
    else
      flash.now[:alert] = response.parse['error']
      render :new, status: :unprocessable_entity
    end
  end

  def edit
    response = HTTP.auth("Token #{session[:token]}").get("http://localhost:8080/api/me/")
    if response.status.success?
      @user = response.parse
    else
      redirect_to root_path, alert: 'Unable to load user settings.'
    end
  end

  def update
    user_data = {
      username: params[:username],
      bio: params[:bio],
    }.compact
  
    response = HTTP.auth("Token #{session[:token]}").patch("http://localhost:8080/api/me/", json: user_data)
  
    if response.status.success?
      flash[:notice] = 'Settings updated successfully.'
      redirect_to edit_user_path
    else
      error_messages = response.parse.map { |field, messages| "#{field.capitalize} #{messages.join(', ')}" }
      flash[:alert] = error_messages.join(". ")
  
      redirect_to edit_user_path
    end
  end
  
  

  private

 
def require_login
  redirect_to "http://#{request.host_with_port}/login" unless session[:token]
end

end
