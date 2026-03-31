namespace ATrustIdentRecord.Type
{

    public static class SexCodeHelper
    {

        public static eSexCode FromString(string input)
        {
            if(0 == string.Compare(input, "m",true) ||
                0 == string.Compare(input, "male", true))
            {
                return eSexCode.Male;
            }
            else if (0 == string.Compare(input, "f", true) ||
                0 == string.Compare(input, "w", true) ||
                0 == string.Compare(input, "female", true))
            {
                return eSexCode.Female;
            }
            else if (0 == string.Compare(input, "c", true) ||
                0 == string.Compare(input, "firma", true) ||
                0 == string.Compare(input, "company", true))
            {
                return eSexCode.Company;
            }
            else if (0 == string.Compare(input, "d", true) ||
                0 == string.Compare(input, "diverse", true) ||
                0 == string.Compare(input, "divers", true))
            {
                return eSexCode.Diverse;
            }
            else if (0 == string.Compare(input, "i", true) ||
                0 == string.Compare(input, "intersex", true))
            {
                return eSexCode.Intersex;
            }
            else if (0 == string.Compare(input, "o", true) ||
                0 == string.Compare(input, "open", true) ||
                0 == string.Compare(input, "offen", true))
            {
                return eSexCode.Open;
            }
            else if (0 == string.Compare(input, "u", true) ||
                0 == string.Compare(input, "unbekannt", true) ||
                0 == string.Compare(input, "unknown", true))
            {
                return eSexCode.Unknown;
            }
            else if (0 == string.Compare(input, "n", true) ||
                0 == string.Compare(input, "k", true) ||
                0 == string.Compare(input, "Keine Angabe", true) ||
                0 == string.Compare(input, "not stated", true) ||
                0 == string.Compare(input, "ns", true))
            {
                return eSexCode.NotStated;
            }

            return eSexCode.Unknown;
        }
    }

}