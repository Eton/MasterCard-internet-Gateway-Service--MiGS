using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(MigsPayments.Startup))]
namespace MigsPayments
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
