class SessionsController < ApplicationController
  def new
  end

  def create
    response = HTTP.post("http://localhost:8080/api/login/", json: { username: params[:username], password: params[:password] })
    if response.status.success?
      session[:token] = response.parse['token']
      redirect_to contracts_path, notice: 'Logged in successfully'
    else
      flash.now[:alert] = 'Invalid credentials'
      render :new, status: :unprocessable_entity
    end
  end

  def destroy
    session[:token] = nil
    redirect_to root_path, notice: 'Logged out successfully'
  end
end
