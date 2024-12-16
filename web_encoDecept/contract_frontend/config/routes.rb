Rails.application.routes.draw do
  root 'contracts#index'
  
  resources :contracts, only: [:index, :show, :new, :create, :edit, :update] do
    collection do
      get 'manage', to: 'contracts#manage'
    end
  end

  resources :contract_templates, only: [:index, :new, :create, :show, :edit, :update, :destroy]

  get 'register', to: 'users#new', as: 'register'
  post 'register', to: 'users#create'
  get 'settings', to: 'users#edit', as: 'edit_user'
  patch 'settings', to: 'users#update'

  get 'login', to: 'sessions#new', as: 'login'
  post 'login', to: 'sessions#create'
  get 'logout', to: 'sessions#destroy', as: 'logout'

  get 'report', to: 'reports#new', as: 'new_report'
  post 'report', to: 'reports#create'
end
