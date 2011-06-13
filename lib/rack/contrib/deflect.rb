require 'thread'
require 'socket'
require 'redis'

# TODO: optional stats
# TODO: performance
# TODO: clean up tests

module Rack

  ##
  # Rack middleware for protecting against Denial-of-service attacks
  # http://en.wikipedia.org/wiki/Denial-of-service_attack.
  #
  # This middleware is designed for small deployments, which most likely
  # are not utilizing load balancing from other software or hardware. Deflect
  # current supports the following functionality:
  #
  # * Saturation prevention (small DoS attacks, or request abuse)
  # * Blacklisting of remote addresses
  # * Whitelisting of remote addresses
  # * Logging
  #
  # === Options:
  #
  #   :log                When false logging will be bypassed, otherwise pass an object responding to #puts
  #   :log_format         Alter the logging format
  #   :log_date_format    Alter the logging date format
  #   :request_threshold  Number of requests allowed within the set :interval. Defaults to 100
  #   :interval           Duration in seconds until the request counter is reset. Defaults to 5
  #   :block_duration     Duration in seconds that a remote address will be blocked. Defaults to 900 (15 minutes)
  #   :whitelist          Array of remote addresses which bypass Deflect. NOTE: this does not block others
  #   :blacklist          Array of remote addresses immediately considered malicious
  #   :ignore_agents      a list of words from user agents allow in.
  #   :redis_interface    The IP and port of the REDIS server that will be used.
  #   :notifier_callback  A callback that will be used for important notifications.
  #
  # === Examples:
  #
  #  use Rack::Deflect, :log => $stdout, :request_threshold => 20, :interval => 2, :block_duration => 60
  #
  # CREDIT: TJ Holowaychuk <tj@vision-media.ca>
  #

  class Deflect

    attr_reader :options
    attr_accessor :redis_storage

    def initialize app, options = {}
      @mutex = Mutex.new
      @local_storage_map = {}
      @app, @options = app, {
        :log => false,
        :log_format => 'deflect(%s): %s',
        :log_date_format => '%m/%d/%Y',
        :request_threshold => 100,
        :interval => 5,
        :block_duration => 900,
        :whitelist => [],
        :blacklist => [],
        :ignore_agents => [],
        :redis_interface => { :host => "127.0.0.1", :port => "6379" },
        :notifier_callback => nil,
        :fresh_start => false
      }.merge(options)
      
      @redis_storage = nil
      begin
        @redis_storage = Redis.new(@options[:redis_interface]) unless @options[:redis_interface].blank?
      rescue Timeout::Error
        # No redis.
      end
      
      if @options[:fresh_start] == true && @redis_storage.present? 
        
        # TODO: check if it's possible to delete keys by using a wildcard option.
        saved_keys = @redis_storage.keys "Deflector*"
        saved_keys.each do |key_name|
          @redis_storage.del key_name
        end
      end
      unless @options[:reset_for].nil?
        @options[:reset_for].each do |addr|
          clear_for_address(addr)
        end
      end
    end

    def call env
      if options[:ignore_agents].any? {|word| env["HTTP_USER_AGENT"].to_s.downcase.include?(word) }
        log "Skipping user agent #{env["HTTP_USER_AGENT"]}"
        status, headers, body = @app.call env
        [status, headers, body]
      else
        return deflect! if deflect? env
        status, headers, body = @app.call env
        [status, headers, body]
      end
    end

    def deflect!
      [403, { 'Content-Type' => 'text/html', 'Content-Length' => '0' }, []]
    end

    def deflect? env
      @env = env
      @remote_addr = env['REMOTE_ADDR']
      return false if options[:whitelist].include? @remote_addr
      return true  if options[:blacklist].include? @remote_addr
      sync { watch }
    end

    def log message
      return unless options[:log]
      options[:log].puts(options[:log_format] % [Time.now.strftime(options[:log_date_format]), message])
    end

    def sync &block
      @mutex.synchronize(&block)
    end

    def watch
      increment_requests
      init_local_storage_map(@remote_addr)
      set_key("expires", Time.now + options[:interval])
      clear! if watch_expired? and not blocked?
      clear! if blocked? and block_expired?
      block! if watching? and exceeded_request_threshold?
      blocked?
    end

    def block!
      return if blocked?
      log "blocked #{@remote_addr}"
      set_key("block_expires", (Time.now + options[:block_duration]).to_s)
      notifier = options[:notifier_callback]
      blocked_uris = get_key("requested_uris")
      notifier.call(@remote_addr, Socket.gethostname, blocked_uris) unless notifier.nil?
    end

    def blocked?
      !(get_key("block_expires").nil?)
    end

    def block_expired?      
      block_expires_str = get_key("block_expires")
      !(block_expires_str.nil?) && (Time.parse(block_expires_str) < Time.now) rescue false
    end

    def watching?
      get_key('requests').to_i > 0
    end

    def clear!
      return unless watching?
      log "released #{@remote_addr}" if blocked?
      clear_for_address(@remote_addr)
    end

    def clear_for_address(address)
      del_key("expires", address)
      del_key("block_expires", address)
      del_key("requests", address)
      del_key("request_uris", address)
    end
    
    def increment_requests
      incr_key("requests")
      log "Current Request: #{@env["REQUEST_URI"]}"
      rrpush("request_uris", "#{@env["REQUEST_METHOD"]} '#{@env["HTTP_HOST"]}#{@env["REQUEST_URI"]}' #{} => #{@env["HTTP_USER_AGENT"]}")
    end

    def exceeded_request_threshold?
      get_key("requests").to_i > options[:request_threshold].to_i
    end

    def watch_expired?
      expires_str = get_key("expires")
      !(expires_str.blank?) && (Time.parse(expires_str) <= Time.now) rescue false
    end
    
    def init_local_storage_map(addr)
      @local_storage_map[addr] = {
        :expires => Time.now + options[:interval],
        :requests => 0,
        :request_uris => []
      }
    end

    def redis_key(key, addr=@remote_addr)
      "Deflector::#{addr}:#{key}"
    end
    
    def set_key(key, val, addr=@remote_addr)
      @local_storage_map[addr.to_sym] = {} if @local_storage_map[addr.to_sym].nil?
      @local_storage_map[addr.to_sym][key.to_sym] = val
      @redis_storage.set(redis_key(key, addr), val) unless @redis_storage.nil?
    end
    
    def get_key(key, addr=@remote_addr)
      val = @redis_storage.get(redis_key(key, addr)) unless @redis_storage.nil?
      val = @local_storage_map[addr.to_sym][key.to_sym] if val.nil? && !(@local_storage_map[addr.to_sym].nil?)
      val
    end
    
    def del_key(key, addr=@remote_addr)
      @local_storage_map[addr.to_sym].delete(key.to_sym) unless @local_storage_map[addr.to_sym].nil?
      @redis_storage.del(redis_key(key, addr)) unless @redis_storage.nil?
    end
    
    def incr_key(key, addr=@remote_addr)
      @local_storage_map[addr.to_sym] = {} if @local_storage_map[addr.to_sym].nil?
      @local_storage_map[addr.to_sym][key.to_sym] = (@local_storage_map[addr.to_sym][key.to_sym].nil? ? 0 : @local_storage_map[addr.to_sym][key.to_sym]) + 1
      @redis_storage.incr(redis_key(key, addr)) unless @redis_storage.nil?
    end
    
    def rrpush(key, val, addr=@remote_addr)
      @local_storage_map[addr.to_sym] = {} if @local_storage_map[addr.to_sym].nil?
      if @local_storage_map[addr.to_sym][key.to_sym]
        @local_storage_map[addr.to_sym][key.to_sym] << val
      else
        @local_storage_map[addr.to_sym][key.to_sym] = [val]
      end
        
      @redis_storage.rpush(redis_key(key, addr), val) unless @redis_storage.nil?
    end
  end
end
