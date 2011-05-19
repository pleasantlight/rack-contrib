require 'test/spec'
require 'rack/mock'
require 'rack/contrib/deflect'

context "Rack::Deflect" do

  setup do
    @app = lambda { |env| [200, { 'Content-Type' => 'text/plain' }, ['cookies']] }
    @mock_addr_1 = '111.111.111.111'
    @mock_addr_2 = '222.222.222.222'
    @mock_addr_3 = '333.333.333.333'
  end

  def mock_env remote_addr, path = '/'
    Rack::MockRequest.env_for path, { 'REMOTE_ADDR' => remote_addr }
  end

  def mock_deflect options = {}    
    options.merge! (:reset_for => [@mock_addr_1, @mock_addr_2, @mock_addr_3])
    Rack::Deflect.new @app, options
  end

  specify "should allow regular requests to follow through" do
    app = mock_deflect
    status, headers, body = app.call mock_env(@mock_addr_1)
    status.should.equal 200
    body.should.equal ['cookies']
  end

  specify "should deflect requests exceeding the request threshold" do
    log = StringIO.new
    app = mock_deflect :request_threshold => 5, :interval => 10, :block_duration => 10, :log => log
    env = mock_env @mock_addr_1

    # First 5 should be fine
    5.times do |i|
      status, headers, body = app.call env
      status.should.equal 200
      body.should.equal ['cookies']
    end

    # Remaining requests should fail for 10 seconds
    10.times do
      status, headers, body = app.call env
      status.should.equal 403
      body.should.equal []
    end

    # Log should reflect that we have blocked an address
    log.string.should.match(/^deflect\(\d+\/\d+\/\d+\): blocked 111.111.111.111\n/)
  end

  specify "should expire blocking" do
    log = StringIO.new
    app = mock_deflect :request_threshold => 5, :interval => 2, :block_duration => 2, :log => log
    env = mock_env @mock_addr_1

    # First 5 should be fine
    5.times do |i|
      status, headers, body = app.call env
      status.should.equal 200
      body.should.equal ['cookies']
    end

    # Exceeds request threshold
    status, headers, body = app.call env
    status.should.equal 403
    body.should.equal []

    # Allow block to expire
    sleep 3

    # Another 5 is fine now
    5.times do
      status, headers, body = app.call env
      status.should.equal 200
      body.should.equal ['cookies']
    end

    # Log should reflect block and release
    log.string.should.match(/deflect.*: blocked 111\.111\.111\.111/)
    log.string.should.match(/deflect.*: released 111\.111\.111\.111/)
  end

  specify "should allow whitelisting of remote addresses" do
    app = mock_deflect :whitelist => [@mock_addr_1], :request_threshold => 5, :interval => 2
    env = mock_env @mock_addr_1

    # Whitelisted addresses are always fine
    10.times do
      status, headers, body = app.call env
      status.should.equal 200
      body.should.equal ['cookies']
    end
  end

  specify "should allow blacklisting of remote addresses" do
    app = mock_deflect :blacklist => [@mock_addr_2]

    status, headers, body = app.call mock_env(@mock_addr_1)
    status.should.equal 200
    body.should.equal ['cookies']

    status, headers, body = app.call mock_env(@mock_addr_2)
    status.should.equal 403
    body.should.equal []
  end

  specify "should call the notifier callback with the correct parameters" do
    @notifier_callback_str = ""

    @notifier_callback = Proc.new do |blocked_addr, hostname, requested_uris|
      @notifier_callback_str << "~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~- #{hostname} blocked IP address #{blocked_addr}. Corresponding requested_uris array has #{requested_uris.nil? ? "0" : requested_uris.len} elements. ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-\n"
    end
   
    app = mock_deflect :request_threshold => 5, :interval => 2, :block_duration => 2, :notifier_callback => @notifier_callback
    env = mock_env @mock_addr_1

    # First 5 should be fine
    5.times do |i|
      status, headers, body = app.call env
      status.should.equal 200
      body.should.equal ['cookies']
    end

    # Exceeds request threshold
    status, headers, body = app.call env
    status.should.equal 403
    body.should.equal []

    # Allow block to expire
    sleep 3

    # Another 5 is fine now
    5.times do
      status, headers, body = app.call env
      status.should.equal 200
      body.should.equal ['cookies']
    end

    # Log should reflect block and release
    @notifier_callback_str.should.match(/blocked IP address 111\.111\.111\.111/)
  end
  
  specify "should fall back to local storage if redis is unavailable" do
    @notifier_callback_str = ""

    @notifier_callback = Proc.new do |blocked_addr, hostname, requested_uris|
      @notifier_callback_str << "~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~- #{hostname} blocked IP address #{blocked_addr}. Corresponding requested_uris array has #{requested_uris.nil? ? "0" : requested_uris.len} elements. ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-\n"
    end
   
    app = mock_deflect :request_threshold => 5, :interval => 2, :block_duration => 2, :notifier_callback => @notifier_callback, :redis_interface => { :host => "127.0.0.2", :port => "6379" }
    env = mock_env @mock_addr_1

    # First 5 should be fine
    5.times do |i|
      status, headers, body = app.call env
      status.should.equal 200
      body.should.equal ['cookies']
    end

    # Exceeds request threshold
    status, headers, body = app.call env
    status.should.equal 403
    body.should.equal []

    # Allow block to expire
    sleep 3

    # Another 5 is fine now
    5.times do
      status, headers, body = app.call env
      status.should.equal 200
      body.should.equal ['cookies']
    end

    # Log should reflect block and release
    @notifier_callback_str.should.match(/blocked IP address 111\.111\.111\.111/)
  end
end
