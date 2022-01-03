using LiteDB;
using Microsoft.Extensions.Options;

namespace esign.Helpers {
    public class LiteDbContext
    {
        public LiteDatabase Database { get; }

        public LiteDbContext(IOptions<LiteDbOptions> options)
        {
            Database = new LiteDatabase(options.Value.DatabaseLocation);
        }
    }

    public class LiteDbOptions
    {
        public string DatabaseLocation { get; set; }
    }
}
