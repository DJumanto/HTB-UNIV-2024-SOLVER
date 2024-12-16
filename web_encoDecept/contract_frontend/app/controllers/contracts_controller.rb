class ContractsController < ApplicationController
  before_action :require_login

  def index
    response = HTTP.auth("Token #{session[:token]}").get("http://localhost:8080/api/contract/")
    @contracts = response.parse if response.status.success?
  end

  def show
    response = HTTP.auth("Token #{session[:token]}").get("http://localhost:8080/api/contracts/#{params[:id]}/")
    @contract = response.parse if response.status.success?
  end

  def new
  end

  def create
    contract_data = {
      title: params[:title],
      description: params[:description],
      amount: params[:amount],
      start_date: params[:start_date],
      end_date: params[:end_date],
      terms: params[:terms]
    }

    response = HTTP.auth("Token #{session[:token]}").post("http://localhost:8080/api/contracts/", json: contract_data)

    if response.status.success?
      flash[:notice] = "Contract created successfully."
      redirect_to contracts_path
    else
      flash.now[:alert] = "Failed to create contract."
      render :new, status: :unprocessable_entity
    end
  end

  def manage
    filtered_params = filter_params
  
    response = if filtered_params.empty?
                 HTTP.auth("Token #{session[:token]}").post("http://localhost:8080/api/contracts/filter/", json: { all: true })
               else
                 HTTP.auth("Token #{session[:token]}").post("http://localhost:8080/api/contracts/filter/", json: filtered_params)
               end
  
    if response.status.success?
      @contracts = response.parse
    else
      @contracts = []
      flash[:alert] = "Failed to load contracts. Please try again."
    end
  end
  

  private

  def filter_params
    params.to_unsafe_h.except('action', 'controller').compact_blank.tap do |filters|
      filters[:start_date] = filters[:start_date].presence&.match(/^\d{4}-\d{2}-\d{2}$/) ? filters[:start_date] : nil
      filters[:end_date] = filters[:end_date].presence&.match(/^\d{4}-\d{2}-\d{2}$/) ? filters[:end_date] : nil
    end.compact
  end
  
def require_login
  redirect_to "http://#{request.host_with_port}/login" unless session[:token]
end
end
