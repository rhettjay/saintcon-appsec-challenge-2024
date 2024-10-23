# Use a Ruby base image
FROM ruby:latest

# Set the working directory
WORKDIR /app

COPY Gemfile Gemfile.lock ./

# Install dependencies
RUN bundle install

# Copy the application code to the container
COPY . .



# Expose the port your Sinatra app is running on
EXPOSE 4568

# Run rake in production
ENV RACK_ENV=production
# Start the Sinatra app
CMD ["ruby", "app.rb"]
