require 'rspec'
require 'json'
require 'yaml'
require 'bosh/template/test'

describe 'dns-audit' do
  let(:release) { Bosh::Template::Test::ReleaseDir.new(File.join(File.dirname(__FILE__), '../..')) }
  let(:job) { release.job('dns-audit') }
  let(:instance) { Bosh::Template::Test::InstanceSpec.new(ip: '10.0.16.20', id: 'cell-guid') }
  let(:properties) { {} }

  describe 'config/dns-audit.json' do
    let(:template) { job.template('config/dns-audit.json') }
    let(:rendered) { JSON.parse(template.render(properties, spec: instance)) }

    it 'renders the defaults' do
      expect(rendered).to eq(
        'enabled' => false,
        'cgroup_root' => '/sys/fs/cgroup/garden',
        'garden_network' => 'unix',
        'garden_address' => '/var/vcap/data/garden/garden.sock',
        'output_log_file' => '/var/vcap/sys/log/dns-audit/dns.log',
        'host_ip' => '10.0.16.20',
        'host_id' => 'cell-guid',
        'properties' => [],
        'dedup_window_seconds' => 60,
        'max_logs_per_second_per_container' => 10,
        'exclude_domains' => [],
        'capture_responses' => false,
        'ring_buffer_size_kb' => 4096,
      )
    end

    context 'with properties' do
      let(:properties) do
        {
          'dns_audit' => {
            'enabled' => true,
            'properties' => ['network.app_id', 'app_name'],
            'dedup_window_seconds' => 30,
            'max_logs_per_second_per_container' => 5,
            'exclude_domains' => ['internal.example'],
            'capture_responses' => true,
            'ring_buffer_size_kb' => 8192,
            'garden_socket' => '/custom/garden.sock',
          },
        }
      end

      it 'renders them' do
        expect(rendered).to include(
          'enabled' => true,
          'properties' => ['network.app_id', 'app_name'],
          'dedup_window_seconds' => 30,
          'max_logs_per_second_per_container' => 5,
          'exclude_domains' => ['internal.example'],
          'capture_responses' => true,
          'ring_buffer_size_kb' => 8192,
          'garden_address' => '/custom/garden.sock',
        )
      end
    end

    [
      ['dedup_window_seconds', 0, /dedup_window_seconds/],
      ['max_logs_per_second_per_container', -1, /max_logs_per_second_per_container/],
      ['ring_buffer_size_kb', 1000, /ring_buffer_size_kb/],
    ].each do |key, value, message|
      context "with an invalid #{key}" do
        let(:properties) { { 'dns_audit' => { key => value } } }

        it 'fails to render' do
          expect { template.render(properties, spec: instance) }.to raise_error(message)
        end
      end
    end
  end

  describe 'config/bpm.yml' do
    let(:template) { job.template('config/bpm.yml') }
    let(:rendered) { YAML.safe_load(template.render(properties)) }

    it 'runs privileged with the cgroup tree and the Garden socket directory' do
      process = rendered['processes'].first
      expect(process['name']).to eq('dns-audit')
      expect(process['executable']).to eq('/var/vcap/packages/dns-audit/bin/dns-audit')
      expect(process['args']).to eq(['-config', '/var/vcap/jobs/dns-audit/config/dns-audit.json'])
      expect(process['unsafe']['privileged']).to be(true)
      expect(process['unsafe']['unrestricted_volumes']).to eq([
        { 'path' => '/sys/fs/cgroup' },
        { 'path' => '/var/vcap/data/garden' },
      ])
    end
  end

  describe 'monit' do
    let(:monit) { File.read(File.join(File.dirname(__FILE__), '../../jobs/dns-audit/monit')) }

    def render_monit(enabled)
      context = Bosh::Template::EvaluationContext.new({ 'properties' => { 'dns_audit' => { 'enabled' => enabled } } }, nil)
      ERB.new(monit, trim_mode: '-').result(context.get_binding)
    end

    it 'runs the process only when enabled' do
      expect(render_monit(false)).not_to include('check process')
      expect(render_monit(true)).to include('check process dns-audit')
      expect(render_monit(true)).to include('/var/vcap/jobs/bpm/bin/bpm start dns-audit')
    end
  end
end
