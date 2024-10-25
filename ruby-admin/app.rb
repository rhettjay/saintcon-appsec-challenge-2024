# frozen_string_literal: true

require 'rubygems'
require 'bundler/setup'
require 'httparty'
require 'sinatra'
require 'securerandom'
require 'pg'
require 'logger'

require_relative 'config'

$stdout.sync = true

enable :sessions
set :session_secret, ENV.fetch('SESSION_SECRET') { SecureRandom.hex(64) }

helpers do
  def db
    @db ||= PG.connect(
      dbname: 'postgres',
      user: settings.pg_user,
      password: settings.pg_password,
      host: settings.pg_host,
      port: settings.pg_port
    )
  end
end

puts "Server running at http://#{settings.bind}:#{settings.port}"

get '/admin/' do
  redirect '/admin/dashboard'
end

post '/admin/login' do
  username = params[:username]
  password = params[:password]

  if valid_credentials?(username, password)
    user_data = db.exec_params("SELECT * FROM users WHERE username = $1", [username])
    if user_data.first['role'] != 'admin'
      return erb :login, locals: { error: 'You must be an admin to view the admin dashboard' }
    end

    session[:user_id] = user_data.first['id']
    session[:username] = username
    session[:role] = user_data.first['role']
    session[:logged_in] = true

    redirect "#{request.scheme}://#{request.host}:#{request.port}/admin/dashboard"
  else
    erb :login, locals: { error: 'Invalid username or password' }
  end
end

get '/admin/login' do
  erb :login, locals: { error: params[:error] }
end

get '/admin/logout' do
  session.clear
  redirect '/admin/login'
end

get '/admin/dashboard' do
  users = db.exec('SELECT * FROM users;')

  @users = users.map do |user|
    user['banned'] = user['banned'] == 't'
    user
  end
  erb :dashboard
end

get '/admin/tos' do
  redirect 'http://youtube.com/watch?v=dQw4w9WgXcQ'
end

post '/admin/ban' do
  halt 403, 'User is unauthorized' if session[:role] != 'admin'
  halt 415, 'Unsupported Media Type' unless request.content_type == 'application/json'

  begin
    data = JSON.parse(request.body.read)
  rescue JSON::ParserError
    halt 400, 'Invalid JSON'
  end

  begin
    db.exec_params('UPDATE users SET banned=true WHERE id=$1', [data['userId'].to_i])
  rescue PG::Error => e
    puts "Database error: #{e.message}"
    halt 500, 'Internal server error'
  end
  status 204
end

post '/admin/unban' do
  halt 403, 'User is unauthorized' if session[:role] != 'admin'
  halt 415, 'Unsupported Media Type' unless request.content_type == 'application/json'

  begin
    data = JSON.parse(request.body.read)
  rescue JSON::ParserError
    halt 400, 'Invalid JSON'
  end

  begin
    db.exec_params('UPDATE users SET banned=false WHERE id=$1', [data['userId']])
  rescue PG::Error => e
    puts "Database error: #{e.message}"
    halt 500, 'Internal server error'
  end
  status 204
end

helpers do
  def valid_credentials?(username, password)
    response = HTTParty.post("#{settings.user_api}/login", body: { username:, password: }.to_json,
                                                           headers: { 'Content-Type' => 'application/json' })
    response.code == 200
  end
end
