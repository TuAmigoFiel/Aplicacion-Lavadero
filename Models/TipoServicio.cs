﻿using Google.Cloud.Firestore;
namespace Firebase.Models
{
    [FirestoreData]
    public class TipoServicio
    {
        [FirestoreProperty]
        public required string Id { get; set; }

        [FirestoreProperty]
        public required string Nombre { get; set; }
    }
}
