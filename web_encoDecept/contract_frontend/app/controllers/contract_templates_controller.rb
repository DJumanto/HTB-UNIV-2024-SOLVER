# app/controllers/contract_templates_controller.rb
class ContractTemplatesController < ApplicationController
  before_action :require_login

  def index
    response = HTTP.auth("Token #{session[:token]}").get("http://localhost:8080/api/contract_templates/")
    @contract_templates = response.parse if response.status.success?
  end

  def new
    @contract_template = {}
  end

  def create
    user_data = current_user
    
    unless user_data && user_data['id']
      flash[:alert] = "User must be logged in to create a template."
      redirect_to login_path and return
    end
    serialized_content = Marshal.dump(params[:content])
  
    response = HTTP.auth("Token #{session[:token]}").post("http://localhost:8080/api/contract_templates/", json: { data: serialized_content, user_id: user_data['id'] }.merge(params.to_unsafe_h))
  
    if response.status.success?
      flash[:notice] = "Template created successfully."
      redirect_to contract_templates_path
    else
      flash.now[:alert] = "Failed to create template."
      render :new
    end
  end
  

  def show
    response = HTTP.auth("Token #{session[:token]}").get("http://localhost:8080/api/contract_templates/#{params[:id]}/")

    if response.status.success?
      @template = response.parse
      
      content = Marshal.load(@template['data']) if @template['data']

      @template['id'] ||= params[:id]
      @template['name'] ||= 'Unnamed Template'
      @template['description'] ||= 'No description provided.'
      @template['data'] = content
      @template['created_at'] ||= Time.current.to_s
    else
      redirect_to contract_templates_path, alert: "Template not found."
    end
  end

  def edit
    response = HTTP.auth("Token #{session[:token]}").get("http://localhost:8080/api/contract_templates/#{params[:id]}/")
    if response.status.success?
      @contract_template = response.parse

      @contract_template['id'] ||= params[:id]
      @contract_template['name'] ||= 'Unnamed Template'
      @contract_template['description'] ||= 'No description provided.'
      @contract_template['data'] = Marshal.load(@contract_template['data']) if @contract_template['data']
      
    else
      flash[:alert] = "Failed to load template for editing."
      redirect_to contract_templates_path
    end
  end
  
  def update
    serialized_content = Marshal.dump(params[:content])
    
    user_id = session[:user_id]
  
    response = HTTP.auth("Token #{session[:token]}").patch("http://localhost:8080/api/contract_templates/#{params[:id]}/",
                          json: {
                            name: params[:name],
                            description: params[:description],
                            data: serialized_content,
                            user_id: user_id # Pass user_id from session
                          })
  
    if response.status.success?
      flash[:notice] = "Template updated successfully."
      redirect_to contract_templates_path
    else
      flash.now[:alert] = "Failed to update template."
      render :edit
    end
  end
  

  def destroy
    response = HTTP.auth("Token #{session[:token]}").delete("http://localhost:8080/api/contract_templates/#{params[:id]}/")
    if response.status.success?
      flash[:notice] = "Template deleted successfully."
    else
      flash[:alert] = "Failed to delete template."
    end
    redirect_to contract_templates_path
  end

  private


  
  def require_login
    redirect_to "http://#{request.host_with_port}/login" unless session[:token]
  end
  
  
end
