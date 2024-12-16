# app/controllers/reports_controller.rb
class ReportsController < ApplicationController
    def new
      # This action renders the report form (if separate from existing view).
    end
  
    def create
      # Send the contract URL to the Django API
      response = HTTP.post("http://localhost:8080/api/submit_report/", json: { contract_url: params[:contract_url] })
  
      if response.status.success?
        flash[:notice] = 'Report submitted successfully.'
      else
        flash[:alert] = 'Failed to submit report.'
      end
  
      redirect_to request.referer || root_path # Redirect back to form or home
    end
  end
  